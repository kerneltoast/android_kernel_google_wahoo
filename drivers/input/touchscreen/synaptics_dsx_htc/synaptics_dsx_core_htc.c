/*
 * Synaptics DSX touchscreen driver
 *
 * Copyright (C) 2012-2015 Synaptics Incorporated. All rights reserved.
 *
 * Copyright (C) 2012 Alexandra Chin <alexandra.chin@tw.synaptics.com>
 * Copyright (C) 2012 Scott Lin <scott.lin@tw.synaptics.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * INFORMATION CONTAINED IN THIS DOCUMENT IS PROVIDED "AS-IS," AND SYNAPTICS
 * EXPRESSLY DISCLAIMS ALL EXPRESS AND IMPLIED WARRANTIES, INCLUDING ANY
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE,
 * AND ANY WARRANTIES OF NON-INFRINGEMENT OF ANY INTELLECTUAL PROPERTY RIGHTS.
 * IN NO EVENT SHALL SYNAPTICS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, PUNITIVE, OR CONSEQUENTIAL DAMAGES ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OF THE INFORMATION CONTAINED IN THIS DOCUMENT, HOWEVER CAUSED
 * AND BASED ON ANY THEORY OF LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, AND EVEN IF SYNAPTICS WAS ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE. IF A TRIBUNAL OF COMPETENT JURISDICTION DOES
 * NOT PERMIT THE DISCLAIMER OF DIRECT DAMAGES OR ANY OTHER DAMAGES, SYNAPTICS'
 * TOTAL CUMULATIVE LIABILITY TO ANY PARTY SHALL NOT EXCEED ONE HUNDRED U.S.
 * DOLLARS.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/input.h>
#include <linux/gpio.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/pinctrl/consumer.h>
#include <linux/input/synaptics_dsx_v2_6.h>
#include "synaptics_dsx_core.h"
#ifdef KERNEL_ABOVE_2_6_38
#include <linux/input/mt.h>
#endif

#define INPUT_PHYS_NAME "synaptics_dsx/touch_input"
#define STYLUS_PHYS_NAME "synaptics_dsx/stylus"

#define VIRTUAL_KEY_MAP_FILE_NAME "virtualkeys." PLATFORM_DRIVER_NAME

#ifdef KERNEL_ABOVE_2_6_38
#define TYPE_B_PROTOCOL
#endif

#define WAKEUP_GESTURE false

#define NO_0D_WHILE_2D
#define REPORT_2D_Z
#define REPORT_2D_W

#define REPORT_2D_PRESSURE
#define TEMP_FORCE_WA
/* #define USE_DATA_SERVER */

#define F12_DATA_15_WORKAROUND

#define IGNORE_FN_INIT_FAILURE

#define RPT_TYPE (1 << 0)
#define RPT_X_LSB (1 << 1)
#define RPT_X_MSB (1 << 2)
#define RPT_Y_LSB (1 << 3)
#define RPT_Y_MSB (1 << 4)
#define RPT_Z (1 << 5)
#define RPT_WX (1 << 6)
#define RPT_WY (1 << 7)
#define RPT_DEFAULT (RPT_TYPE | RPT_X_LSB | RPT_X_MSB | RPT_Y_LSB | RPT_Y_MSB)

#define REBUILD_WORK_DELAY_MS 500 /* ms */

#define EXP_FN_WORK_DELAY_MS 500 /* ms */
#define MAX_F11_TOUCH_WIDTH 15
#define MAX_F12_TOUCH_WIDTH 255
#define MAX_F12_TOUCH_PRESSURE 255

#define CHECK_STATUS_TIMEOUT_MS 100

#define F01_STD_QUERY_LEN 21
#define F01_BUID_ID_OFFSET 18
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
#define F01_CHIP_ID_OFFSET 17
#endif

#define STATUS_NO_ERROR 0x00
#define STATUS_RESET_OCCURRED 0x01
#define STATUS_INVALID_CONFIG 0x02
#define STATUS_DEVICE_FAILURE 0x03
#define STATUS_CONFIG_CRC_FAILURE 0x04
#define STATUS_FIRMWARE_CRC_FAILURE 0x05
#define STATUS_CRC_IN_PROGRESS 0x06

#define NORMAL_OPERATION (0 << 0)
#define SENSOR_SLEEP (1 << 0)
#define NO_SLEEP_OFF (0 << 2)
#define NO_SLEEP_ON (1 << 2)
#define CONFIGURED (1 << 7)

#define F11_CONTINUOUS_MODE 0x00
#define F11_WAKEUP_GESTURE_MODE 0x04
#define F12_CONTINUOUS_MODE 0x00
#define F12_WAKEUP_GESTURE_MODE 0x02
#define F12_UDG_DETECT 0x0f

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
#define V5V6_CONFIG_ID_SIZE 4
#define V7_CONFIG_ID_SIZE 32
#define SHIFT_BITS (10)

#define REPORT_INDEX_OFFSET 1
#define REPORT_DATA_OFFSET 3
#define NO_SELF_CAPACITY_DATA 0
#define READ_DIFF_DATA 2
#define READ_RAW_DATA 3
#define READ_DIFF_SELF_DATA 59
#define READ_RAW_SELF_DATA 63

#define FREQ_MASK 0x7F

static DECLARE_WAIT_QUEUE_HEAD(syn_data_ready_wq);
struct timespec time_start, time_end, time_delta;
static uint32_t debug_mask = 0x0000000;
#endif

extern int msm_gpio_install_direct_irq(unsigned int gpio,
		unsigned int irq,
		unsigned int input_polarity);

static int synaptics_rmi4_check_status(struct synaptics_rmi4_data *rmi4_data,
		bool *was_in_bl_mode);
static int synaptics_rmi4_free_fingers(struct synaptics_rmi4_data *rmi4_data);
static int synaptics_rmi4_reinit_device(struct synaptics_rmi4_data *rmi4_data);
static int synaptics_rmi4_reset_device(struct synaptics_rmi4_data *rmi4_data,
		bool rebuild);
static int synaptics_rmi4_hw_reset_device(struct synaptics_rmi4_data *rmi4_data);
static irqreturn_t synaptics_rmi4_irq(int irq, void *data);

#ifdef CONFIG_FB
static void synaptics_pm_worker(struct work_struct *work);
static int synaptics_rmi4_fb_notifier_cb(struct notifier_block *self,
		unsigned long event, void *data);
#endif

#ifdef CONFIG_HAS_EARLYSUSPEND
#ifndef CONFIG_FB
#define USE_EARLYSUSPEND
#endif
#endif

#ifdef USE_EARLYSUSPEND
static void synaptics_rmi4_early_suspend(struct early_suspend *h);

static void synaptics_rmi4_late_resume(struct early_suspend *h);
#endif

static int synaptics_rmi4_suspend(struct device *dev);

static int synaptics_rmi4_resume(struct device *dev);

static ssize_t synaptics_rmi4_f01_reset_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

static ssize_t synaptics_rmi4_f01_productinfo_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t synaptics_rmi4_f01_buildid_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t synaptics_rmi4_f01_flashprog_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t synaptics_rmi4_0dbutton_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t synaptics_rmi4_0dbutton_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

static ssize_t synaptics_rmi4_suspend_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

static ssize_t synaptics_rmi4_wake_gesture_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t synaptics_rmi4_wake_gesture_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
static ssize_t synaptics_rmi4_wake_event_show(struct device *dev,
		struct device_attribute *attr, char *buf);
#endif

#ifdef USE_DATA_SERVER
static ssize_t synaptics_rmi4_synad_pid_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);
#endif

static ssize_t synaptics_rmi4_virtual_key_map_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf);

static ssize_t synaptics_rmi4_i2c_switch_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t synaptics_rmi4_i2c_switch_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

struct synaptics_rmi4_f01_device_status {
	union {
		struct {
			unsigned char status_code:4;
			unsigned char reserved:2;
			unsigned char flash_prog:1;
			unsigned char unconfigured:1;
		} __packed;
		unsigned char data[1];
	};
};

struct synaptics_rmi4_f11_query_0_5 {
	union {
		struct {
			/* query 0 */
			unsigned char f11_query0_b0__2:3;
			unsigned char has_query_9:1;
			unsigned char has_query_11:1;
			unsigned char has_query_12:1;
			unsigned char has_query_27:1;
			unsigned char has_query_28:1;

			/* query 1 */
			unsigned char num_of_fingers:3;
			unsigned char has_rel:1;
			unsigned char has_abs:1;
			unsigned char has_gestures:1;
			unsigned char has_sensitibity_adjust:1;
			unsigned char f11_query1_b7:1;

			/* query 2 */
			unsigned char num_of_x_electrodes;

			/* query 3 */
			unsigned char num_of_y_electrodes;

			/* query 4 */
			unsigned char max_electrodes:7;
			unsigned char f11_query4_b7:1;

			/* query 5 */
			unsigned char abs_data_size:2;
			unsigned char has_anchored_finger:1;
			unsigned char has_adj_hyst:1;
			unsigned char has_dribble:1;
			unsigned char has_bending_correction:1;
			unsigned char has_large_object_suppression:1;
			unsigned char has_jitter_filter:1;
		} __packed;
		unsigned char data[6];
	};
};

struct synaptics_rmi4_f11_query_7_8 {
	union {
		struct {
			/* query 7 */
			unsigned char has_single_tap:1;
			unsigned char has_tap_and_hold:1;
			unsigned char has_double_tap:1;
			unsigned char has_early_tap:1;
			unsigned char has_flick:1;
			unsigned char has_press:1;
			unsigned char has_pinch:1;
			unsigned char has_chiral_scroll:1;

			/* query 8 */
			unsigned char has_palm_detect:1;
			unsigned char has_rotate:1;
			unsigned char has_touch_shapes:1;
			unsigned char has_scroll_zones:1;
			unsigned char individual_scroll_zones:1;
			unsigned char has_multi_finger_scroll:1;
			unsigned char has_multi_finger_scroll_edge_motion:1;
			unsigned char has_multi_finger_scroll_inertia:1;
		} __packed;
		unsigned char data[2];
	};
};

struct synaptics_rmi4_f11_query_9 {
	union {
		struct {
			unsigned char has_pen:1;
			unsigned char has_proximity:1;
			unsigned char has_large_object_sensitivity:1;
			unsigned char has_suppress_on_large_object_detect:1;
			unsigned char has_two_pen_thresholds:1;
			unsigned char has_contact_geometry:1;
			unsigned char has_pen_hover_discrimination:1;
			unsigned char has_pen_hover_and_edge_filters:1;
		} __packed;
		unsigned char data[1];
	};
};

struct synaptics_rmi4_f11_query_12 {
	union {
		struct {
			unsigned char has_small_object_detection:1;
			unsigned char has_small_object_detection_tuning:1;
			unsigned char has_8bit_w:1;
			unsigned char has_2d_adjustable_mapping:1;
			unsigned char has_general_information_2:1;
			unsigned char has_physical_properties:1;
			unsigned char has_finger_limit:1;
			unsigned char has_linear_cofficient_2:1;
		} __packed;
		unsigned char data[1];
	};
};

struct synaptics_rmi4_f11_query_27 {
	union {
		struct {
			unsigned char f11_query27_b0:1;
			unsigned char has_pen_position_correction:1;
			unsigned char has_pen_jitter_filter_coefficient:1;
			unsigned char has_group_decomposition:1;
			unsigned char has_wakeup_gesture:1;
			unsigned char has_small_finger_correction:1;
			unsigned char has_data_37:1;
			unsigned char f11_query27_b7:1;
		} __packed;
		unsigned char data[1];
	};
};

struct synaptics_rmi4_f11_ctrl_6_9 {
	union {
		struct {
			unsigned char sensor_max_x_pos_7_0;
			unsigned char sensor_max_x_pos_11_8:4;
			unsigned char f11_ctrl7_b4__7:4;
			unsigned char sensor_max_y_pos_7_0;
			unsigned char sensor_max_y_pos_11_8:4;
			unsigned char f11_ctrl9_b4__7:4;
		} __packed;
		unsigned char data[4];
	};
};

struct synaptics_rmi4_f11_data_1_5 {
	union {
		struct {
			unsigned char x_position_11_4;
			unsigned char y_position_11_4;
			unsigned char x_position_3_0:4;
			unsigned char y_position_3_0:4;
			unsigned char wx:4;
			unsigned char wy:4;
			unsigned char z;
		} __packed;
		unsigned char data[5];
	};
};

struct synaptics_rmi4_f12_query_5 {
	union {
		struct {
			unsigned char size_of_query6;
			struct {
				unsigned char ctrl0_is_present:1;
				unsigned char ctrl1_is_present:1;
				unsigned char ctrl2_is_present:1;
				unsigned char ctrl3_is_present:1;
				unsigned char ctrl4_is_present:1;
				unsigned char ctrl5_is_present:1;
				unsigned char ctrl6_is_present:1;
				unsigned char ctrl7_is_present:1;
			} __packed;
			struct {
				unsigned char ctrl8_is_present:1;
				unsigned char ctrl9_is_present:1;
				unsigned char ctrl10_is_present:1;
				unsigned char ctrl11_is_present:1;
				unsigned char ctrl12_is_present:1;
				unsigned char ctrl13_is_present:1;
				unsigned char ctrl14_is_present:1;
				unsigned char ctrl15_is_present:1;
			} __packed;
			struct {
				unsigned char ctrl16_is_present:1;
				unsigned char ctrl17_is_present:1;
				unsigned char ctrl18_is_present:1;
				unsigned char ctrl19_is_present:1;
				unsigned char ctrl20_is_present:1;
				unsigned char ctrl21_is_present:1;
				unsigned char ctrl22_is_present:1;
				unsigned char ctrl23_is_present:1;
			} __packed;
			struct {
				unsigned char ctrl24_is_present:1;
				unsigned char ctrl25_is_present:1;
				unsigned char ctrl26_is_present:1;
				unsigned char ctrl27_is_present:1;
				unsigned char ctrl28_is_present:1;
				unsigned char ctrl29_is_present:1;
				unsigned char ctrl30_is_present:1;
				unsigned char ctrl31_is_present:1;
			} __packed;
			struct {
				unsigned char ctrl32_is_present:1;
				unsigned char ctrl33_is_present:1;
				unsigned char ctrl34_is_present:1;
				unsigned char ctrl35_is_present:1;
				unsigned char ctrl36_is_present:1;
				unsigned char ctrl37_is_present:1;
				unsigned char ctrl38_is_present:1;
				unsigned char ctrl39_is_present:1;
			} __packed;
			struct {
				unsigned char ctrl40_is_present:1;
				unsigned char ctrl41_is_present:1;
				unsigned char ctrl42_is_present:1;
				unsigned char ctrl43_is_present:1;
				unsigned char ctrl44_is_present:1;
				unsigned char ctrl45_is_present:1;
				unsigned char ctrl46_is_present:1;
				unsigned char ctrl47_is_present:1;
			} __packed;
			struct {
				unsigned char ctrl48_is_present:1;
				unsigned char ctrl49_is_present:1;
				unsigned char ctrl50_is_present:1;
				unsigned char ctrl51_is_present:1;
				unsigned char ctrl52_is_present:1;
				unsigned char ctrl53_is_present:1;
				unsigned char ctrl54_is_present:1;
				unsigned char ctrl55_is_present:1;
			} __packed;
			struct {
				unsigned char ctrl56_is_present:1;
				unsigned char ctrl57_is_present:1;
				unsigned char ctrl58_is_present:1;
				unsigned char ctrl59_is_present:1;
				unsigned char ctrl60_is_present:1;
				unsigned char ctrl61_is_present:1;
				unsigned char ctrl62_is_present:1;
				unsigned char ctrl63_is_present:1;
			} __packed;
		};
		unsigned char data[9];
	};
};

struct synaptics_rmi4_f12_query_8 {
	union {
		struct {
			unsigned char size_of_query9;
			struct {
				unsigned char data0_is_present:1;
				unsigned char data1_is_present:1;
				unsigned char data2_is_present:1;
				unsigned char data3_is_present:1;
				unsigned char data4_is_present:1;
				unsigned char data5_is_present:1;
				unsigned char data6_is_present:1;
				unsigned char data7_is_present:1;
			} __packed;
			struct {
				unsigned char data8_is_present:1;
				unsigned char data9_is_present:1;
				unsigned char data10_is_present:1;
				unsigned char data11_is_present:1;
				unsigned char data12_is_present:1;
				unsigned char data13_is_present:1;
				unsigned char data14_is_present:1;
				unsigned char data15_is_present:1;
			} __packed;
			struct {
				unsigned char data16_is_present:1;
				unsigned char data17_is_present:1;
				unsigned char data18_is_present:1;
				unsigned char data19_is_present:1;
				unsigned char data20_is_present:1;
				unsigned char data21_is_present:1;
				unsigned char data22_is_present:1;
				unsigned char data23_is_present:1;
			} __packed;
			struct {
				unsigned char data24_is_present:1;
				unsigned char data25_is_present:1;
				unsigned char data26_is_present:1;
				unsigned char data27_is_present:1;
				unsigned char data28_is_present:1;
				unsigned char data29_is_present:1;
				unsigned char data30_is_present:1;
				unsigned char data31_is_present:1;
			} __packed;
		};
		unsigned char data[5];
	};
};

struct synaptics_rmi4_f12_ctrl_8 {
	union {
		struct {
			unsigned char max_x_coord_lsb;
			unsigned char max_x_coord_msb;
			unsigned char max_y_coord_lsb;
			unsigned char max_y_coord_msb;
			unsigned char rx_pitch_lsb;
			unsigned char rx_pitch_msb;
			unsigned char tx_pitch_lsb;
			unsigned char tx_pitch_msb;
			unsigned char low_rx_clip;
			unsigned char high_rx_clip;
			unsigned char low_tx_clip;
			unsigned char high_tx_clip;
			unsigned char num_of_rx;
			unsigned char num_of_tx;
		};
		unsigned char data[14];
	};
};

struct synaptics_rmi4_f12_ctrl_18 {
	union {
		struct {
			unsigned char double_tap_x0_lsb:8;
			unsigned char double_tap_x0_msb:8;
			unsigned char double_tap_y0_lsb:8;
			unsigned char double_tap_y0_msb:8;
			unsigned char double_tap_x1_lsb:8;
			unsigned char double_tap_x1_msb:8;
			unsigned char double_tap_y1_lsb:8;
			unsigned char double_tap_y1_msb:8;
		};
		unsigned char data[8];
	};
};

struct synaptics_rmi4_f12_ctrl_23 {
	union {
		struct {
			unsigned char finger_enable:1;
			unsigned char active_stylus_enable:1;
			unsigned char palm_enable:1;
			unsigned char unclassified_object_enable:1;
			unsigned char hovering_finger_enable:1;
			unsigned char gloved_finger_enable:1;
			unsigned char f12_ctr23_00_b6__7:2;
			unsigned char max_reported_objects;
			unsigned char f12_ctr23_02_b0:1;
			unsigned char report_active_stylus_as_finger:1;
			unsigned char report_palm_as_finger:1;
			unsigned char report_unclassified_object_as_finger:1;
			unsigned char report_hovering_finger_as_finger:1;
			unsigned char report_gloved_finger_as_finger:1;
			unsigned char report_narrow_object_swipe_as_finger:1;
			unsigned char report_handedge_as_finger:1;
			unsigned char cover_enable:1;
			unsigned char stylus_enable:1;
			unsigned char eraser_enable:1;
			unsigned char small_object_enable:1;
			unsigned char f12_ctr23_03_b4__7:4;
			unsigned char report_cover_as_finger:1;
			unsigned char report_stylus_as_finger:1;
			unsigned char report_eraser_as_finger:1;
			unsigned char report_small_object_as_finger:1;
			unsigned char f12_ctr23_04_b4__7:4;
		};
		unsigned char data[5];
	};
};

struct synaptics_rmi4_f12_ctrl_27 {
	union {
		struct {
			unsigned char double_tap_enable:1;
			unsigned char swipe_enable:1;
			unsigned char tap_and_hold_enable:1;
			unsigned char circle_enable:1;
			unsigned char triangle_enable:1;
			unsigned char vee_enable:1;
			unsigned char unicode_enable:1;
			unsigned char unused:1;
			unsigned char lpwg_report_rate:8;
			unsigned char false_activation_threshold:8;
			unsigned char maximum_active_duration:8;
			unsigned char timer_1_duration:8;
			unsigned char maximum_active_duration_timeout:8;
		};
		unsigned char data[6];
	};
};

struct synaptics_rmi4_f12_ctrl_31 {
	union {
		struct {
			unsigned char max_x_coord_lsb;
			unsigned char max_x_coord_msb;
			unsigned char max_y_coord_lsb;
			unsigned char max_y_coord_msb;
			unsigned char rx_pitch_lsb;
			unsigned char rx_pitch_msb;
			unsigned char rx_clip_low;
			unsigned char rx_clip_high;
			unsigned char wedge_clip_low;
			unsigned char wedge_clip_high;
			unsigned char num_of_p;
			unsigned char num_of_q;
		};
		unsigned char data[12];
	};
};

struct synaptics_rmi4_f12_ctrl_58 {
	union {
		struct {
			unsigned char reporting_format;
			unsigned char f12_ctr58_00_reserved;
			unsigned char min_force_lsb;
			unsigned char min_force_msb;
			unsigned char max_force_lsb;
			unsigned char max_force_msb;
			unsigned char light_press_threshold_lsb;
			unsigned char light_press_threshold_msb;
			unsigned char light_press_hysteresis_lsb;
			unsigned char light_press_hysteresis_msb;
			unsigned char hard_press_threshold_lsb;
			unsigned char hard_press_threshold_msb;
			unsigned char hard_press_hysteresis_lsb;
			unsigned char hard_press_hysteresis_msb;
		};
		unsigned char data[14];
	};
};

struct synaptics_rmi4_f12_finger_data {
	unsigned char object_type_and_status;
	unsigned char x_lsb;
	unsigned char x_msb;
	unsigned char y_lsb;
	unsigned char y_msb;
#ifdef REPORT_2D_Z
	unsigned char z;
#endif
#ifdef REPORT_2D_W
	unsigned char wx;
	unsigned char wy;
#endif
};

struct synaptics_rmi4_f1a_query {
	union {
		struct {
			unsigned char max_button_count:3;
			unsigned char f1a_query0_b3__4:2;
			unsigned char has_query4:1;
			unsigned char has_query3:1;
			unsigned char has_query2:1;
			unsigned char has_general_control:1;
			unsigned char has_interrupt_enable:1;
			unsigned char has_multibutton_select:1;
			unsigned char has_tx_rx_map:1;
			unsigned char has_perbutton_threshold:1;
			unsigned char has_release_threshold:1;
			unsigned char has_strongestbtn_hysteresis:1;
			unsigned char has_filter_strength:1;
		} __packed;
		unsigned char data[2];
	};
};

struct synaptics_rmi4_f1a_query_4 {
	union {
		struct {
			unsigned char has_ctrl19:1;
			unsigned char f1a_query4_b1__4:4;
			unsigned char has_ctrl24:1;
			unsigned char f1a_query4_b6__7:2;
		} __packed;
		unsigned char data[1];
	};
};

struct synaptics_rmi4_f1a_control_0 {
	union {
		struct {
			unsigned char multibutton_report:2;
			unsigned char filter_mode:2;
			unsigned char reserved:4;
		} __packed;
		unsigned char data[1];
	};
};

struct synaptics_rmi4_f1a_control {
	struct synaptics_rmi4_f1a_control_0 general_control;
	unsigned char button_int_enable;
	unsigned char multi_button;
	unsigned char *txrx_map;
	unsigned char *button_threshold;
	unsigned char button_release_threshold;
	unsigned char strongest_button_hysteresis;
	unsigned char filter_strength;
};

struct synaptics_rmi4_f1a_handle {
	int button_bitmask_size;
	unsigned char max_count;
	unsigned char valid_button_count;
	unsigned char *button_data_buffer;
	unsigned char *button_map;
	struct synaptics_rmi4_f1a_query button_query;
	struct synaptics_rmi4_f1a_control button_control;
};

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
struct synaptics_rmi4_f54_query {
	union {
		struct {
			/* query 0 */
			unsigned char num_of_rx_electrodes;

			/* query 1 */
			unsigned char num_of_tx_electrodes;

			/* query 2 */
			unsigned char f54_query2_b0__1:2;
			unsigned char has_baseline:1;
			unsigned char has_image8:1;
			unsigned char f54_query2_b4__5:2;
			unsigned char has_image16:1;
			unsigned char f54_query2_b7:1;

			/* queries 3.0 and 3.1 */
			unsigned short clock_rate;

			/* query 4 */
			unsigned char touch_controller_family;

			/* query 5 */
			unsigned char has_pixel_touch_threshold_adjustment:1;
			unsigned char f54_query5_b1__7:7;

			/* query 6 */
			unsigned char has_sensor_assignment:1;
			unsigned char has_interference_metric:1;
			unsigned char has_sense_frequency_control:1;
			unsigned char has_firmware_noise_mitigation:1;
			unsigned char has_ctrl11:1;
			unsigned char has_two_byte_report_rate:1;
			unsigned char has_one_byte_report_rate:1;
			unsigned char has_relaxation_control:1;

			/* query 7 */
			unsigned char curve_compensation_mode:2;
			unsigned char f54_query7_b2__7:6;

			/* query 8 */
			unsigned char f54_query8_b0:1;
			unsigned char has_iir_filter:1;
			unsigned char has_cmn_removal:1;
			unsigned char has_cmn_maximum:1;
			unsigned char has_touch_hysteresis:1;
			unsigned char has_edge_compensation:1;
			unsigned char has_per_frequency_noise_control:1;
			unsigned char has_enhanced_stretch:1;

			/* query 9 */
			unsigned char has_force_fast_relaxation:1;
			unsigned char has_multi_metric_state_machine:1;
			unsigned char has_signal_clarity:1;
			unsigned char has_variance_metric:1;
			unsigned char has_0d_relaxation_control:1;
			unsigned char has_0d_acquisition_control:1;
			unsigned char has_status:1;
			unsigned char has_slew_metric:1;

			/* query 10 */
			unsigned char has_h_blank:1;
			unsigned char has_v_blank:1;
			unsigned char has_long_h_blank:1;
			unsigned char has_startup_fast_relaxation:1;
			unsigned char has_esd_control:1;
			unsigned char has_noise_mitigation2:1;
			unsigned char has_noise_state:1;
			unsigned char has_energy_ratio_relaxation:1;

			/* query 11 */
			unsigned char has_excessive_noise_reporting:1;
			unsigned char has_slew_option:1;
			unsigned char has_two_overhead_bursts:1;
			unsigned char has_query13:1;
			unsigned char has_one_overhead_burst:1;
			unsigned char f54_query11_b5:1;
			unsigned char has_ctrl88:1;
			unsigned char has_query15:1;

			/* query 12 */
			unsigned char number_of_sensing_frequencies:4;
			unsigned char f54_query12_b4__7:4;
		} __packed;
		unsigned char data[14];
	};
};

struct synaptics_rmi4_f54_query_13 {
	union {
		struct {
			unsigned char has_ctrl86:1;
			unsigned char has_ctrl87:1;
			unsigned char has_ctrl87_sub0:1;
			unsigned char has_ctrl87_sub1:1;
			unsigned char has_ctrl87_sub2:1;
			unsigned char has_cidim:1;
			unsigned char has_noise_mitigation_enhancement:1;
			unsigned char has_rail_im:1;
		} __packed;
		unsigned char data[1];
	};
};

struct synaptics_rmi4_f54_query_15 {
	union {
		struct {
			unsigned char has_ctrl90:1;
			unsigned char has_transmit_strength:1;
			unsigned char has_ctrl87_sub3:1;
			unsigned char has_query16:1;
			unsigned char has_query20:1;
			unsigned char has_query21:1;
			unsigned char has_query22:1;
			unsigned char has_query25:1;
		} __packed;
		unsigned char data[1];
	};
};

struct synaptics_rmi4_f54_query_16 {
	union {
		struct {
			unsigned char has_query17:1;
			unsigned char has_data17:1;
			unsigned char has_ctrl92:1;
			unsigned char has_ctrl93:1;
			unsigned char has_ctrl94_query18:1;
			unsigned char has_ctrl95_query19:1;
			unsigned char has_ctrl99:1;
			unsigned char has_ctrl100:1;
		} __packed;
		unsigned char data[1];
	};
};
#endif

struct synaptics_rmi4_exp_fhandler {
	struct synaptics_rmi4_exp_fn *exp_fn;
	bool insert;
	bool remove;
	struct list_head link;
};

struct synaptics_rmi4_exp_fn_data {
	bool initialized;
	bool queue_work;
	struct mutex mutex;
	struct list_head list;
	struct delayed_work work;
	struct workqueue_struct *workqueue;
	struct synaptics_rmi4_data *rmi4_data;
};

static struct synaptics_rmi4_exp_fn_data exp_data;

static struct synaptics_dsx_button_map *vir_button_map;

#ifdef USE_DATA_SERVER
static pid_t synad_pid;
static struct task_struct *synad_task;
static struct siginfo interrupt_signal;
#endif

static struct device_attribute attrs[] = {
	__ATTR(reset, S_IRUGO | S_IWUSR | S_IWGRP,
			synaptics_rmi4_show_error,
			synaptics_rmi4_f01_reset_store),
	__ATTR(productinfo, S_IRUGO,
			synaptics_rmi4_f01_productinfo_show,
			synaptics_rmi4_store_error),
	__ATTR(buildid, S_IRUGO,
			synaptics_rmi4_f01_buildid_show,
			synaptics_rmi4_store_error),
	__ATTR(flashprog, S_IRUGO,
			synaptics_rmi4_f01_flashprog_show,
			synaptics_rmi4_store_error),
	__ATTR(0dbutton, (S_IRUGO | S_IWUSR | S_IWGRP),
			synaptics_rmi4_0dbutton_show,
			synaptics_rmi4_0dbutton_store),
	__ATTR(suspend, S_IRUGO | S_IWUSR | S_IWGRP,
			synaptics_rmi4_show_error,
			synaptics_rmi4_suspend_store),
	__ATTR(wake_gesture, (S_IRUGO | S_IWUSR | S_IWGRP),
			synaptics_rmi4_wake_gesture_show,
			synaptics_rmi4_wake_gesture_store),
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	__ATTR(wake_event, (S_IRUGO),
			synaptics_rmi4_wake_event_show,
			synaptics_rmi4_store_error),
#endif
#ifdef USE_DATA_SERVER
	__ATTR(synad_pid, S_IRUGO | S_IWUSR | S_IWGRP,
			synaptics_rmi4_show_error,
			synaptics_rmi4_synad_pid_store),
#endif
	__ATTR(i2c_switch, (S_IRUGO | S_IWUSR | S_IWGRP),
			synaptics_rmi4_i2c_switch_show,
			synaptics_rmi4_i2c_switch_store),
};

static struct kobj_attribute virtual_key_map_attr = {
	.attr = {
		.name = VIRTUAL_KEY_MAP_FILE_NAME,
		.mode = S_IRUGO,
	},
	.show = synaptics_rmi4_virtual_key_map_show,
};

static ssize_t synaptics_rmi4_f01_reset_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int retval;
	unsigned int reset;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	if (sscanf(buf, "%u", &reset) != 1)
		return -EINVAL;

	if (reset != 1)
		return -EINVAL;

	retval = synaptics_rmi4_reset_device(rmi4_data, false);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to issue reset command, error = %d\n",
				__func__, retval);
		return retval;
	}

	return count;
}

static ssize_t synaptics_rmi4_f01_productinfo_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "0x%02x 0x%02x\n",
			(rmi4_data->rmi4_mod_info.product_info[0]),
			(rmi4_data->rmi4_mod_info.product_info[1]));
}

static ssize_t synaptics_rmi4_f01_buildid_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%u\n",
			rmi4_data->firmware_id);
}

static ssize_t synaptics_rmi4_f01_flashprog_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int retval;
	struct synaptics_rmi4_f01_device_status device_status;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	retval = synaptics_rmi4_reg_read(rmi4_data,
			rmi4_data->f01_data_base_addr,
			device_status.data,
			sizeof(device_status.data));
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to read device status, error = %d\n",
				__func__, retval);
		return retval;
	}

	return snprintf(buf, PAGE_SIZE, "%u\n",
			device_status.flash_prog);
}

static ssize_t synaptics_rmi4_0dbutton_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%u\n",
			rmi4_data->button_0d_enabled);
}

static ssize_t synaptics_rmi4_0dbutton_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int retval;
	unsigned int input;
	unsigned char ii;
	unsigned char intr_enable;
	struct synaptics_rmi4_fn *fhandler;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);
	struct synaptics_rmi4_device_info *rmi;

	rmi = &(rmi4_data->rmi4_mod_info);

	if (sscanf(buf, "%u", &input) != 1)
		return -EINVAL;

	input = input > 0 ? 1 : 0;

	if (rmi4_data->button_0d_enabled == input)
		return count;

	if (list_empty(&rmi->support_fn_list))
		return -ENODEV;

	list_for_each_entry(fhandler, &rmi->support_fn_list, link) {
		if (fhandler->fn_number == SYNAPTICS_RMI4_F1A) {
			ii = fhandler->intr_reg_num;

			retval = synaptics_rmi4_reg_read(rmi4_data,
					rmi4_data->f01_ctrl_base_addr + 1 + ii,
					&intr_enable,
					sizeof(intr_enable));
			if (retval < 0)
				return retval;

			if (input == 1)
				intr_enable |= fhandler->intr_mask;
			else
				intr_enable &= ~fhandler->intr_mask;

			retval = synaptics_rmi4_reg_write(rmi4_data,
					rmi4_data->f01_ctrl_base_addr + 1 + ii,
					&intr_enable,
					sizeof(intr_enable));
			if (retval < 0)
				return retval;
		}
	}

	rmi4_data->button_0d_enabled = input;

	return count;
}

static ssize_t synaptics_rmi4_suspend_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned int input;

	if (sscanf(buf, "%u", &input) != 1)
		return -EINVAL;

	if (input == 1)
		synaptics_rmi4_suspend(dev);
	else if (input == 0)
		synaptics_rmi4_resume(dev);
	else
		return -EINVAL;

	return count;
}

static ssize_t synaptics_rmi4_wake_gesture_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%u\n",
			rmi4_data->enable_wakeup_gesture);
}

static ssize_t synaptics_rmi4_wake_gesture_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned int input;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	if (sscanf(buf, "%u", &input) != 1)
		return -EINVAL;

	input = input > 0 ? 1 : 0;

	if (rmi4_data->f11_wakeup_gesture || rmi4_data->f12_wakeup_gesture)
		rmi4_data->enable_wakeup_gesture = WAKEUP_GESTURE && input;

	return count;
}

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
static ssize_t synaptics_rmi4_wake_event_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "0\n");
}
#endif

static ssize_t synaptics_rmi4_i2c_switch_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);
	int gpio = rmi4_data->hw_if->board_data->switch_gpio;

	return snprintf(buf, PAGE_SIZE, "%d\n", gpio_get_value(gpio));
}

static ssize_t synaptics_rmi4_i2c_switch_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned int input;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);
	int gpio = rmi4_data->hw_if->board_data->switch_gpio;

	if (kstrtoint(buf, 10, &input))
		return -EINVAL;

	gpio_set_value(gpio, input ? 1 : 0);

	return count;
}

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
static ssize_t synaptics_reset_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	struct synaptics_rmi4_data *rmi4_data = exp_data.rmi4_data;
	unsigned int reset;

	pr_info("%s\n", __func__);
	if (sscanf(buf, "%u", &reset) != 1)
		return -EINVAL;

	if (reset != 1)
		return -EINVAL;

	ret = synaptics_rmi4_hw_reset_device(rmi4_data);
	if (ret < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to issue reset command, error = %ld\n",
				__func__, ret);
		return ret;
	}

	return count;
}

static ssize_t synaptics_debug_show(struct device *dev, struct device_attribute *attr,
	char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%08X\n", debug_mask);
}

static ssize_t synaptics_debug_store(struct device *dev, struct device_attribute *attr,
	const char *buf, size_t count)
{
	if (sscanf(buf, "%ux", &debug_mask) != 1) {
		pr_err("bad parameter");
		return -EINVAL;
	}

	return count;
}

static ssize_t touch_vendor_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	ssize_t ret = 0;
	struct synaptics_rmi4_data *rmi4_data = exp_data.rmi4_data;

	const struct synaptics_dsx_board_data *bdata =
			rmi4_data->hw_if->board_data;

	ret = snprintf(buf, PAGE_SIZE, "synaptics-%d", rmi4_data->chip_id);

	if (bdata->tw_pin_mask != 0)
		ret += scnprintf(buf+ret, PAGE_SIZE-ret, "_twID-0x%x", rmi4_data->tw_vendor);
/*
	if (strlen(rmi4_data->lcm_vendor))
		ret += scnprintf(buf+ret, PAGE_SIZE-ret, "_LCM-%s", rmi4_data->lcm_vendor);
*/
	ret += scnprintf(buf+ret, PAGE_SIZE-ret, "_PR: %d\n", rmi4_data->firmware_id);

	return ret;
}

static ssize_t touch_config_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	ssize_t ret = 0;
	struct synaptics_rmi4_data *rmi4_data = exp_data.rmi4_data;

	ret = snprintf(buf, PAGE_SIZE, "config_version:%s\n", rmi4_data->config_version);

	return ret;
}

int synaptics_read_diag_data(struct synaptics_rmi4_data *rmi4_data)
{
	unsigned char cmd = 0x01;
	int retval = 0;

	retval = synaptics_rmi4_reg_write(rmi4_data,
			rmi4_data->f54_data_base_addr,
			&rmi4_data->diag_command,
			sizeof(rmi4_data->diag_command));
	if (retval < 0) {
		dev_info(rmi4_data->pdev->dev.parent,
				"%s: Failed to write report type\n",
				__func__);
		return retval;
	}

	atomic_set(&rmi4_data->data_ready, 0);

	retval = synaptics_rmi4_reg_write(rmi4_data,
			rmi4_data->f54_cmd_base_addr,
			&cmd,
			sizeof(cmd));
	if (retval < 0) {
		atomic_set(&rmi4_data->data_ready, 1);
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to write get report command\n",
				__func__);
		return retval;
	}

	wait_event_interruptible_timeout(syn_data_ready_wq,
			atomic_read(&rmi4_data->data_ready), 50);

	//Read the self-capacity data
	switch (rmi4_data->diag_command) {
		case READ_DIFF_DATA:
			rmi4_data->diag_command = READ_DIFF_SELF_DATA;
			retval = synaptics_read_diag_data(rmi4_data);
			break;
		case READ_RAW_DATA:
			rmi4_data->diag_command = READ_RAW_SELF_DATA;
			retval = synaptics_read_diag_data(rmi4_data);
			break;
		case READ_DIFF_SELF_DATA:
			rmi4_data->diag_command = READ_DIFF_DATA;
			break;
		case READ_RAW_SELF_DATA:
			rmi4_data->diag_command = READ_RAW_DATA;
			break;
		default:
			retval = NO_SELF_CAPACITY_DATA;
			dev_info(rmi4_data->pdev->dev.parent,
					"%s: no self-capacity data\n",
					__func__);
			break;
	}

	return retval;
}

static ssize_t synaptics_diag_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = exp_data.rmi4_data;
	size_t count = 0;
	int retval = 0;
	uint16_t i, j;

	retval = synaptics_read_diag_data(rmi4_data);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to get diag data\n",
				__func__);
		return retval;
	}

	for (i = 0; i < rmi4_data->num_of_tx; i++) {
		for (j = 0; j < rmi4_data->num_of_rx; j++) {
			switch (rmi4_data->chip_id) {
				case 2200:
				case 3202:
				case 7508:
					count += snprintf(buf + count, PAGE_SIZE, "%5d",
							rmi4_data->report_data[i + j * rmi4_data->num_of_tx]);
					break;
				//case 3201:
				//case 3508:
				//case 3528:
				//case 3351:
				default:
					count += snprintf(buf + count, PAGE_SIZE, "%5d",
							rmi4_data->report_data[i * rmi4_data->num_of_rx + j]);
					break;
			}
		}
		if (retval != NO_SELF_CAPACITY_DATA)
			count += snprintf(buf + count, PAGE_SIZE, "\t  %5d\n",
					rmi4_data->report_data_32[rmi4_data->num_of_rx + i]);
		count += snprintf(buf + count, PAGE_SIZE, "\n");
	}

	if (retval != NO_SELF_CAPACITY_DATA) {
		count += snprintf(buf + count, PAGE_SIZE, "\n");
		for (i = 0; i < rmi4_data->num_of_rx; i += 2)
			count += snprintf(buf + count, PAGE_SIZE, "%5d     ",
					rmi4_data->report_data_32[i]);
		count += snprintf(buf + count, PAGE_SIZE, "\n");
		for (i = 1; i < rmi4_data->num_of_rx; i += 2)
			count += snprintf(buf + count, PAGE_SIZE, "     %5d",
					rmi4_data->report_data_32[i]);
		count += snprintf(buf + count, PAGE_SIZE, "\n");
	}

	return count;
}

static ssize_t synaptics_diag_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct synaptics_rmi4_data *rmi4_data = exp_data.rmi4_data;

	if (buf[0] == '1')
		rmi4_data->diag_command = READ_DIFF_DATA;
	else if (buf[0] == '2')
		rmi4_data->diag_command = READ_RAW_DATA;

	return count;
}

static ssize_t int_status_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct synaptics_rmi4_data *rmi4_data = exp_data.rmi4_data;
	size_t count = 0;

	count += snprintf(buf + count, PAGE_SIZE, "%d ", rmi4_data->irq_enabled);
	count += snprintf(buf + count, PAGE_SIZE, "\n");

	return count;
}

static ssize_t int_status_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct synaptics_rmi4_data *rmi4_data = exp_data.rmi4_data;
	int value;

	if (sysfs_streq(buf, "0"))
		value = false;
	else if (sysfs_streq(buf, "1"))
		value = true;
	else
		return -EINVAL;

	mutex_lock(&(rmi4_data->rmi4_irq_enable_mutex));

	if (value) {
		enable_irq(rmi4_data->irq);
		rmi4_data->irq_enabled = true;
		pr_info("%s: interrupt enable: %x\n", __func__,
			rmi4_data->irq_enabled);
	} else {
		disable_irq(rmi4_data->irq);
		rmi4_data->irq_enabled = false;
		pr_info("%s: interrupt disable: %x\n", __func__,
			rmi4_data->irq_enabled);
	}

	mutex_unlock(&(rmi4_data->rmi4_irq_enable_mutex));

	return count;
}

static DEVICE_ATTR(reset, S_IWUSR, NULL, synaptics_reset_store);
static DEVICE_ATTR(debug_level, (S_IWUSR|S_IRUGO), synaptics_debug_show, synaptics_debug_store);
static DEVICE_ATTR(vendor, S_IRUGO, touch_vendor_show, NULL);
static DEVICE_ATTR(config, S_IRUGO, touch_config_show, NULL);
static DEVICE_ATTR(diag, (S_IWUSR | S_IRUGO), synaptics_diag_show, synaptics_diag_store);
static DEVICE_ATTR(enabled, (S_IWUSR|S_IRUGO), int_status_show, int_status_store);

static struct attribute *htc_attrs[] = {
	&dev_attr_reset.attr,
	&dev_attr_debug_level.attr,
	&dev_attr_vendor.attr,
	&dev_attr_config.attr,
	&dev_attr_diag.attr,
	&dev_attr_enabled.attr,
	NULL
};

static const struct attribute_group attr_group = {
	.attrs = htc_attrs,
};

static struct kobject *android_touch_kobj;
static int synaptics_rmi4_sysfs_init(struct synaptics_rmi4_data *rmi4_data, bool enable)
{
	if (enable) {
		android_touch_kobj = kobject_create_and_add("android_touch", NULL);
		if (android_touch_kobj == NULL) {
			dev_err(rmi4_data->pdev->dev.parent,"%s: subsystem_register failed\n", __func__);
			return -ENOMEM;
		}

		if (sysfs_create_link(android_touch_kobj, &rmi4_data->input_dev->dev.kobj, "synaptics_rmi4_dsx") < 0) {
			dev_err(rmi4_data->pdev->dev.parent, "%s: failed to create link\n", __func__);
			return -ENOMEM;
		}

		if (sysfs_create_group(android_touch_kobj, &attr_group) < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to create sysfs attributes\n",
					__func__);
			return -ENODEV;
		}
	} else {
		sysfs_remove_link(android_touch_kobj, "synaptics_rmi4_dsx");
		sysfs_remove_group(android_touch_kobj, &attr_group);
		kobject_del(android_touch_kobj);
		dev_info(rmi4_data->pdev->dev.parent,
				"%s: sysfs attributes are removed\n",
				__func__);
	}

	return 0;
}
#endif

#ifdef USE_DATA_SERVER
static ssize_t synaptics_rmi4_synad_pid_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned int input;

	if (sscanf(buf, "%u", &input) != 1)
		return -EINVAL;

	synad_pid = input;
	pr_notice("%s: Use data server and synad_pid =%d\n", __func__, synad_pid);
	if (synad_pid) {
		synad_task = pid_task(find_vpid(synad_pid), PIDTYPE_PID);
		if (!synad_task)
			return -EINVAL;
	}

	return count;
}
#endif

static ssize_t synaptics_rmi4_virtual_key_map_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	int ii;
	int cnt;
	int count = 0;

	for (ii = 0; ii < vir_button_map->nbuttons; ii++) {
		cnt = snprintf(buf, PAGE_SIZE - count, "0x01:%d:%d:%d:%d:%d\n",
				vir_button_map->map[ii * 5 + 0],
				vir_button_map->map[ii * 5 + 1],
				vir_button_map->map[ii * 5 + 2],
				vir_button_map->map[ii * 5 + 3],
				vir_button_map->map[ii * 5 + 4]);
		buf += cnt;
		count += cnt;
	}

	return count;
}

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
static void report_wake_event(struct synaptics_rmi4_data *rmi4_data)
{
	sysfs_notify(&rmi4_data->input_dev->dev.kobj, NULL, "wake_event");
}

static unsigned short synaptics_sqrt(unsigned int num)
{
	unsigned short root, remainder, place;

	root = 0;
	remainder = num;
	place = 0x4000;

	while (place > remainder)
		place = place >> 2;
	while (place)
	{
		if (remainder >= root + place)
		{
			remainder = remainder - root - place;
			root = root + (place << 1);
		}
		root = root >> 1;
		place = place >> 2;
	}

	return root;
}

static int synaptics_rmi4_get_noise_state(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	uint8_t data[2], ns = 0, freq = 0;
	uint16_t im = 0, cidim = 0;
	struct synaptics_rmi4_noise_state noise_state;

	retval = synaptics_rmi4_reg_read(rmi4_data,
			rmi4_data->f54_data_base_addr + rmi4_data->f54_im_offset,
			data, sizeof(data));
	if (retval < 0)
		return retval;
	im = (data[1] << 8) | data[0];

	retval = synaptics_rmi4_reg_read(rmi4_data,
			rmi4_data->f54_data_base_addr + rmi4_data->f54_ns_offset,
			&ns, sizeof(ns));
	if (retval < 0)
		return retval;

	retval = synaptics_rmi4_reg_read(rmi4_data,
			rmi4_data->f54_data_base_addr + rmi4_data->f54_cidim_offset,
			data, sizeof(data));
	if (retval < 0)
		return retval;
	cidim = (data[1] << 8) | data[0];

	retval = synaptics_rmi4_reg_read(rmi4_data,
			rmi4_data->f54_data_base_addr + rmi4_data->f54_freq_offset,
			&freq, sizeof(freq));
	if (retval < 0)
		return retval;
	freq &= FREQ_MASK;

	noise_state.im_m = (im > rmi4_data->noise_state.im_m) ?
			im : rmi4_data->noise_state.im_m;
	noise_state.cidim_m = (cidim > rmi4_data->noise_state.cidim_m) ?
			cidim : rmi4_data->noise_state.cidim_m;
	noise_state.im = im;
	noise_state.cidim = cidim;
	noise_state.freq = freq;
	noise_state.ns = ns;

	if((noise_state.freq != rmi4_data->noise_state.freq) ||
			(noise_state.ns != rmi4_data->noise_state.ns)) {
		pr_info("[NS]: IM:%d(M-%d), CIDIM:%d(M-%d), Freq:%d, NS:%d\n",
				im,
				noise_state.im_m,
				cidim,
				noise_state.cidim_m,
				freq,
				ns);
		noise_state.im_m = 0;
		noise_state.cidim_m = 0;
	}

	memcpy(&rmi4_data->noise_state, &noise_state, sizeof(noise_state));

	return 0;
}
#endif

static int synaptics_rmi4_f11_abs_report(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler)
{
	int retval;
	unsigned char touch_count = 0; /* number of touch points */
	unsigned char reg_index;
	unsigned char finger;
	unsigned char fingers_supported;
	unsigned char num_of_finger_status_regs;
	unsigned char finger_shift;
	unsigned char finger_status;
	unsigned char finger_status_reg[3];
	unsigned char detected_gestures;
	unsigned short data_addr;
	unsigned short data_offset;
	int x;
	int y;
	int wx;
	int wy;
	int temp;
	struct synaptics_rmi4_f11_data_1_5 data;
	struct synaptics_rmi4_f11_extra_data *extra_data;

	/*
	 * The number of finger status registers is determined by the
	 * maximum number of fingers supported - 2 bits per finger. So
	 * the number of finger status registers to read is:
	 * register_count = ceil(max_num_of_fingers / 4)
	 */
	fingers_supported = fhandler->num_of_data_points;
	num_of_finger_status_regs = (fingers_supported + 3) / 4;
	data_addr = fhandler->full_addr.data_base;

	extra_data = (struct synaptics_rmi4_f11_extra_data *)fhandler->extra;

	if (rmi4_data->suspend && rmi4_data->enable_wakeup_gesture) {
		retval = synaptics_rmi4_reg_read(rmi4_data,
				data_addr + extra_data->data38_offset,
				&detected_gestures,
				sizeof(detected_gestures));
		if (retval < 0)
			return 0;

		if (detected_gestures) {
			input_report_key(rmi4_data->input_dev, KEY_WAKEUP, 1);
			input_sync(rmi4_data->input_dev);
			input_report_key(rmi4_data->input_dev, KEY_WAKEUP, 0);
			input_sync(rmi4_data->input_dev);
			rmi4_data->suspend = false;
		}

		return 0;
	}

	retval = synaptics_rmi4_reg_read(rmi4_data,
			data_addr,
			finger_status_reg,
			num_of_finger_status_regs);
	if (retval < 0)
		return 0;

	mutex_lock(&(rmi4_data->rmi4_report_mutex));

	for (finger = 0; finger < fingers_supported; finger++) {
		reg_index = finger / 4;
		finger_shift = (finger % 4) * 2;
		finger_status = (finger_status_reg[reg_index] >> finger_shift)
				& MASK_2BIT;

		/*
		 * Each 2-bit finger status field represents the following:
		 * 00 = finger not present
		 * 01 = finger present and data accurate
		 * 10 = finger present but data may be inaccurate
		 * 11 = reserved
		 */
#ifdef TYPE_B_PROTOCOL
		input_mt_slot(rmi4_data->input_dev, finger);
		input_mt_report_slot_state(rmi4_data->input_dev,
				MT_TOOL_FINGER, finger_status);
#endif

		if (finger_status) {
			data_offset = data_addr +
					num_of_finger_status_regs +
					(finger * sizeof(data.data));
			retval = synaptics_rmi4_reg_read(rmi4_data,
					data_offset,
					data.data,
					sizeof(data.data));
			if (retval < 0) {
				touch_count = 0;
				goto exit;
			}

			x = (data.x_position_11_4 << 4) | data.x_position_3_0;
			y = (data.y_position_11_4 << 4) | data.y_position_3_0;
			wx = data.wx;
			wy = data.wy;

			if (rmi4_data->hw_if->board_data->swap_axes) {
				temp = x;
				x = y;
				y = temp;
				temp = wx;
				wx = wy;
				wy = temp;
			}

			if (rmi4_data->hw_if->board_data->x_flip)
				x = rmi4_data->sensor_max_x - x;
			if (rmi4_data->hw_if->board_data->y_flip)
				y = rmi4_data->sensor_max_y - y;
#if !IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
			input_report_key(rmi4_data->input_dev,
					BTN_TOUCH, 1);
			input_report_key(rmi4_data->input_dev,
					BTN_TOOL_FINGER, 1);
#endif
			input_report_abs(rmi4_data->input_dev,
					ABS_MT_POSITION_X, x);
			input_report_abs(rmi4_data->input_dev,
					ABS_MT_POSITION_Y, y);
#ifdef REPORT_2D_W
			input_report_abs(rmi4_data->input_dev,
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
					ABS_MT_TOUCH_MAJOR, synaptics_sqrt(wx*wx + wy*wy));
#else
					ABS_MT_TOUCH_MAJOR, max(wx, wy));
#endif
			input_report_abs(rmi4_data->input_dev,
					ABS_MT_TOUCH_MINOR, min(wx, wy));
#endif
#ifndef TYPE_B_PROTOCOL
			input_mt_sync(rmi4_data->input_dev);
#endif

			dev_dbg(rmi4_data->pdev->dev.parent,
					"%s: Finger %d: status = 0x%02x, x = %d, y = %d, wx = %d, wy = %d\n",
					__func__, finger,
					finger_status,
					x, y, wx, wy);

			touch_count++;
		}
	}

	if (touch_count == 0) {
#if !IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
		input_report_key(rmi4_data->input_dev,
				BTN_TOUCH, 0);
		input_report_key(rmi4_data->input_dev,
				BTN_TOOL_FINGER, 0);
#endif
#ifndef TYPE_B_PROTOCOL
		input_mt_sync(rmi4_data->input_dev);
#endif
	}

	input_sync(rmi4_data->input_dev);

exit:
	mutex_unlock(&(rmi4_data->rmi4_report_mutex));

	return touch_count;
}

static int synaptics_rmi4_f12_abs_report(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler)
{
	int retval;
	unsigned char touch_count = 0; /* number of touch points */
	unsigned char index;
	unsigned char finger;
	unsigned char fingers_to_process;
	unsigned char finger_status;
	unsigned char size_of_2d_data;
	unsigned char gesture_type;
	unsigned short data_addr;
	int x;
	int y;
	int wx;
	int wy;
	int temp;
#if defined(REPORT_2D_PRESSURE) || defined(F51_DISCRETE_FORCE)
	int pressure;
#endif
#ifdef REPORT_2D_PRESSURE
	unsigned char f_fingers;
	unsigned char f_lsb;
	unsigned char f_msb;
	unsigned char *f_data;
#endif
#ifdef F51_DISCRETE_FORCE
	unsigned char force_level;
#endif
	struct synaptics_rmi4_f12_extra_data *extra_data;
	struct synaptics_rmi4_f12_finger_data *data;
	struct synaptics_rmi4_f12_finger_data *finger_data;
	static unsigned char finger_presence;
	static unsigned char stylus_presence;
#ifdef F12_DATA_15_WORKAROUND
	static unsigned char objects_already_present;
#endif
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	int state = 0;
#endif

	fingers_to_process = fhandler->num_of_data_points;
	data_addr = fhandler->full_addr.data_base;
	extra_data = (struct synaptics_rmi4_f12_extra_data *)fhandler->extra;
	size_of_2d_data = sizeof(struct synaptics_rmi4_f12_finger_data);

	if (rmi4_data->suspend && rmi4_data->enable_wakeup_gesture) {
		retval = synaptics_rmi4_reg_read(rmi4_data,
				data_addr + extra_data->data4_offset,
				rmi4_data->gesture_detection,
				sizeof(rmi4_data->gesture_detection));
		if (retval < 0)
			return 0;

		gesture_type = rmi4_data->gesture_detection[0];

		if (gesture_type && gesture_type != F12_UDG_DETECT) {
			dev_info(rmi4_data->pdev->dev.parent, "%s, Double-Tap wake up\n",
					__func__);
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
			report_wake_event(rmi4_data);
#else
			input_report_key(rmi4_data->input_dev, KEY_WAKEUP, 1);
			input_sync(rmi4_data->input_dev);
			input_report_key(rmi4_data->input_dev, KEY_WAKEUP, 0);
			input_sync(rmi4_data->input_dev);
#endif
		}

		return 0;
	}

	/* Determine the total number of fingers to process */
	if (extra_data->data15_size) {
		retval = synaptics_rmi4_reg_read(rmi4_data,
				data_addr + extra_data->data15_offset,
				extra_data->data15_data,
				extra_data->data15_size);
		if (retval < 0)
			return 0;

		/* Start checking from the highest bit */
		index = extra_data->data15_size - 1; /* Highest byte */
		finger = (fingers_to_process - 1) % 8; /* Highest bit */
		do {
			if (extra_data->data15_data[index] & (1 << finger))
				break;

			if (finger) {
				finger--;
			} else if (index > 0) {
				index--; /* Move to the next lower byte */
				finger = 7;
			}

			fingers_to_process--;
		} while (fingers_to_process);

		dev_dbg(rmi4_data->pdev->dev.parent,
			"%s: Number of fingers to process = %d\n",
			__func__, fingers_to_process);
	}

#ifdef F12_DATA_15_WORKAROUND
	fingers_to_process = max(fingers_to_process, objects_already_present);
#endif

	if (!fingers_to_process) {
		synaptics_rmi4_free_fingers(rmi4_data);
		finger_presence = 0;
		stylus_presence = 0;
		return 0;
	}

	retval = synaptics_rmi4_reg_read(rmi4_data,
			data_addr + extra_data->data1_offset,
			(unsigned char *)fhandler->data,
			fingers_to_process * size_of_2d_data);
	if (retval < 0)
		return 0;

	data = (struct synaptics_rmi4_f12_finger_data *)fhandler->data;

#ifdef REPORT_2D_PRESSURE
	if (rmi4_data->report_pressure) {
		retval = synaptics_rmi4_reg_read(rmi4_data,
				data_addr + extra_data->data29_offset,
				extra_data->data29_data,
				extra_data->data29_size);
		if (retval < 0)
			return 0;
	}
#endif

	mutex_lock(&(rmi4_data->rmi4_report_mutex));

	for (finger = 0; finger < fingers_to_process; finger++) {
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
		if (debug_mask & BIT(3))
			rmi4_data->report_points[finger].finger_ind = 0;
#endif
		finger_data = data + finger;
		finger_status = finger_data->object_type_and_status;

#ifdef F12_DATA_15_WORKAROUND
		objects_already_present = finger + 1;
#endif

		x = (finger_data->x_msb << 8) | (finger_data->x_lsb);
		y = (finger_data->y_msb << 8) | (finger_data->y_lsb);
#ifdef REPORT_2D_W
		wx = finger_data->wx;
		wy = finger_data->wy;
#endif

		if (rmi4_data->hw_if->board_data->swap_axes) {
			temp = x;
			x = y;
			y = temp;
			temp = wx;
			wx = wy;
			wy = temp;
		}

		if (rmi4_data->hw_if->board_data->x_flip)
			x = rmi4_data->sensor_max_x - x;
		if (rmi4_data->hw_if->board_data->y_flip)
			y = rmi4_data->sensor_max_y - y;

		switch (finger_status) {
		case F12_FINGER_STATUS:
		case F12_GLOVED_FINGER_STATUS:
			/* Stylus has priority over fingers */
			if (stylus_presence)
				break;
#ifdef TYPE_B_PROTOCOL
			input_mt_slot(rmi4_data->input_dev, finger);
			input_mt_report_slot_state(rmi4_data->input_dev,
					MT_TOOL_FINGER, 1);
#endif
#if !IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
			input_report_key(rmi4_data->input_dev,
					BTN_TOUCH, 1);
			input_report_key(rmi4_data->input_dev,
					BTN_TOOL_FINGER, 1);
#endif
			input_report_abs(rmi4_data->input_dev,
					ABS_MT_POSITION_X, x);
			input_report_abs(rmi4_data->input_dev,
					ABS_MT_POSITION_Y, y);
#ifdef REPORT_2D_W
			if (rmi4_data->wedge_sensor) {
				input_report_abs(rmi4_data->input_dev,
						ABS_MT_TOUCH_MAJOR, wx);
				input_report_abs(rmi4_data->input_dev,
						ABS_MT_TOUCH_MINOR, wx);
			} else {
				input_report_abs(rmi4_data->input_dev,
						ABS_MT_TOUCH_MAJOR,
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
						synaptics_sqrt(wx*wx + wy*wy));
#else
						max(wx, wy));
#endif
				input_report_abs(rmi4_data->input_dev,
						ABS_MT_TOUCH_MINOR,
						min(wx, wy));
			}
#endif
#ifdef REPORT_2D_PRESSURE
			if (rmi4_data->report_pressure) {
				f_fingers = extra_data->data29_size / 2;
				f_data = extra_data->data29_data;
				if (finger + 1 > f_fingers) {
					pressure = rmi4_data->force_min;
				} else {
					f_lsb = finger * 2;
					f_msb = finger * 2 + 1;
					pressure = (int)f_data[f_lsb] << 0 |
							(int)f_data[f_msb] << 8;
#ifdef TEMP_FORCE_WA
					pressure = (int)f_data[f_lsb];
#endif
				}
				pressure = pressure > 0 ? pressure : 1;
				input_report_abs(rmi4_data->input_dev,
						ABS_MT_PRESSURE, pressure);
			} else {
				pressure = finger_data->z;
				input_report_abs(rmi4_data->input_dev,
						ABS_MT_PRESSURE, pressure);
			}
#elif defined(F51_DISCRETE_FORCE)
			if (finger == 0) {
				retval = synaptics_rmi4_reg_read(rmi4_data,
						FORCE_LEVEL_ADDR,
						&force_level,
						sizeof(force_level));
				if (retval < 0)
					return 0;
				pressure = force_level > 0 ? force_level : 1;
			} else {
				pressure = 1;
			}
			input_report_abs(rmi4_data->input_dev,
					ABS_MT_PRESSURE, pressure);
#endif
#ifndef TYPE_B_PROTOCOL
			input_mt_sync(rmi4_data->input_dev);
#endif

#if !IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
			dev_dbg(rmi4_data->pdev->dev.parent,
					"%s: Finger %d: status = 0x%02x, x = %d, y = %d, wx = %d, wy = %d\n",
					__func__, finger,
					finger_status,
					x, y, wx, wy);
#endif

			finger_presence = 1;
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
			if(debug_mask & BIT(1))
				if (rmi4_data->width_factor && rmi4_data->height_factor)
					pr_info("%s: Finger %d: status = 0x%02x, x = %d, y = %d, wx = %d, wy = %d\n",
							__func__, finger,
							finger_status,
							(x * rmi4_data->width_factor)>>SHIFT_BITS,
							(y * rmi4_data->height_factor)>>SHIFT_BITS,
							wx, wy);

			if (debug_mask & BIT(3)) {
				if (rmi4_data->width_factor && rmi4_data->height_factor) {
					rmi4_data->report_points[finger].x = (x * rmi4_data->width_factor)>>SHIFT_BITS;
					rmi4_data->report_points[finger].y = (y * rmi4_data->height_factor)>>SHIFT_BITS;
				}
				state  = 1;
				if(rmi4_data->report_points[finger].state != state) {
					rmi4_data->report_points[finger].finger_ind = finger + 1;
					rmi4_data->report_points[finger].dnup = 1;
					rmi4_data->report_points[finger].wx = wx;
					rmi4_data->report_points[finger].wy = wy;
					rmi4_data->report_points[finger].z = pressure;
				}
				rmi4_data->report_points[finger].state = state;
			}
#endif

			touch_count++;
			break;
		case F12_PALM_STATUS:
			dev_dbg(rmi4_data->pdev->dev.parent,
					"%s: Finger %d: x = %d, y = %d, wx = %d, wy = %d\n",
					__func__, finger,
					x, y, wx, wy);
			break;
		case F12_STYLUS_STATUS:
		case F12_ERASER_STATUS:
			if (!rmi4_data->stylus_enable)
				break;
			/* Stylus has priority over fingers */
			if (finger_presence) {
				mutex_unlock(&(rmi4_data->rmi4_report_mutex));
				synaptics_rmi4_free_fingers(rmi4_data);
				mutex_lock(&(rmi4_data->rmi4_report_mutex));
				finger_presence = 0;
			}
			if (stylus_presence) {/* Allow one stylus at a timee */
				if (finger + 1 != stylus_presence)
					break;
			}
			input_report_key(rmi4_data->stylus_dev,
					BTN_TOUCH, 1);
			if (finger_status == F12_STYLUS_STATUS) {
				input_report_key(rmi4_data->stylus_dev,
						BTN_TOOL_PEN, 1);
			} else {
				input_report_key(rmi4_data->stylus_dev,
						BTN_TOOL_RUBBER, 1);
			}
			input_report_abs(rmi4_data->stylus_dev,
					ABS_X, x);
			input_report_abs(rmi4_data->stylus_dev,
					ABS_Y, y);
			input_sync(rmi4_data->stylus_dev);

			stylus_presence = finger + 1;
			touch_count++;
			break;
		default:
#ifdef TYPE_B_PROTOCOL
			input_mt_slot(rmi4_data->input_dev, finger);
			input_mt_report_slot_state(rmi4_data->input_dev,
					MT_TOOL_FINGER, 0);
#endif
			if(rmi4_data->report_pressure == true)
				input_report_abs(rmi4_data->input_dev, ABS_MT_PRESSURE, 0);
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
			if (debug_mask & BIT(3)) {
				state = 0;
				if (rmi4_data->report_points[finger].state != state) {
					rmi4_data->report_points[finger].finger_ind = finger+1;
					rmi4_data->report_points[finger].dnup = 0;
					rmi4_data->report_points[finger].wx = wx;
					rmi4_data->report_points[finger].wy = wy;
				}
				rmi4_data->report_points[finger].state = state;
			}
#endif
			break;
		}
	}

	if (touch_count == 0) {
		finger_presence = 0;
#ifdef F12_DATA_15_WORKAROUND
		objects_already_present = 0;
#endif
#if !IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
		input_report_key(rmi4_data->input_dev,
				BTN_TOUCH, 0);
		input_report_key(rmi4_data->input_dev,
				BTN_TOOL_FINGER, 0);
#endif
#ifndef TYPE_B_PROTOCOL
		input_mt_sync(rmi4_data->input_dev);
#endif

		if (rmi4_data->stylus_enable) {
			stylus_presence = 0;
			input_report_key(rmi4_data->stylus_dev,
					BTN_TOUCH, 0);
			input_report_key(rmi4_data->stylus_dev,
					BTN_TOOL_PEN, 0);
			if (rmi4_data->eraser_enable) {
				input_report_key(rmi4_data->stylus_dev,
						BTN_TOOL_RUBBER, 0);
			}
			input_sync(rmi4_data->stylus_dev);
		}

		if(rmi4_data->report_pressure == true)
			input_report_abs(rmi4_data->input_dev, ABS_MT_PRESSURE, 0);
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
		if (debug_mask & BIT(3)) {
			for (finger = 0; finger < fingers_to_process; finger++) {
				state = 0;
				if (rmi4_data->report_points[finger].state != state) {
					rmi4_data->report_points[finger].finger_ind = finger+1;
					rmi4_data->report_points[finger].dnup = 0;
					rmi4_data->report_points[finger].wx = wx;
					rmi4_data->report_points[finger].wy = wy;
				}
				rmi4_data->report_points[finger].state = state;
			}
		}
#endif
	}

	input_sync(rmi4_data->input_dev);

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	if (debug_mask & BIT(2)) {
		getnstimeofday(&time_end);
		time_delta.tv_nsec = (time_end.tv_sec*1000000000+time_end.tv_nsec)
			-(time_start.tv_sec*1000000000+time_start.tv_nsec);
		pr_info("Touch latency = %ld us\n", time_delta.tv_nsec/1000);
	}

	if (debug_mask & BIT(3)) {
		for (finger = 0; finger < fingers_to_process; finger++) {
			if(rmi4_data->report_points[finger].finger_ind != 0) {
				if (rmi4_data->width_factor && rmi4_data->height_factor) {
					if(rmi4_data->report_points[finger].dnup)
						pr_info("Screen:F[%02d]:%s, X=%d, Y=%d, Wx=%d, Wy=%d, Z=%d\n",
								rmi4_data->report_points[finger].finger_ind,
								"Down",
								rmi4_data->report_points[finger].x,
								rmi4_data->report_points[finger].y,
								rmi4_data->report_points[finger].wx,
								rmi4_data->report_points[finger].wy,
								rmi4_data->report_points[finger].z);
					else
						pr_info("Screen:F[%02d]:%s, X=%d, Y=%d, Wx=%d, Wy=%d, Z=%d\n",
								rmi4_data->report_points[finger].finger_ind,
								"Up",
								rmi4_data->report_points[finger].x,
								rmi4_data->report_points[finger].y,
								rmi4_data->report_points[finger].wx,
								rmi4_data->report_points[finger].wy,
								rmi4_data->report_points[finger].z);
				}
			}
		}
	}
#endif

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	synaptics_rmi4_get_noise_state(rmi4_data);
#endif

	mutex_unlock(&(rmi4_data->rmi4_report_mutex));

	return touch_count;
}

static void synaptics_rmi4_f1a_report(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler)
{
	int retval;
	unsigned char touch_count = 0;
	unsigned char button;
	unsigned char index;
	unsigned char shift;
	unsigned char status;
	unsigned char *data;
	unsigned short data_addr = fhandler->full_addr.data_base;
	struct synaptics_rmi4_f1a_handle *f1a = fhandler->data;
	static unsigned char do_once = 1;
	static bool current_status[MAX_NUMBER_OF_BUTTONS];
#ifdef NO_0D_WHILE_2D
	static bool before_2d_status[MAX_NUMBER_OF_BUTTONS];
	static bool while_2d_status[MAX_NUMBER_OF_BUTTONS];
#endif

	if (do_once) {
		memset(current_status, 0, sizeof(current_status));
#ifdef NO_0D_WHILE_2D
		memset(before_2d_status, 0, sizeof(before_2d_status));
		memset(while_2d_status, 0, sizeof(while_2d_status));
#endif
		do_once = 0;
	}

	retval = synaptics_rmi4_reg_read(rmi4_data,
			data_addr,
			f1a->button_data_buffer,
			f1a->button_bitmask_size);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to read button data registers\n",
				__func__);
		return;
	}

	data = f1a->button_data_buffer;

	mutex_lock(&(rmi4_data->rmi4_report_mutex));

	for (button = 0; button < f1a->valid_button_count; button++) {
		index = button / 8;
		shift = button % 8;
		status = ((data[index] >> shift) & MASK_1BIT);

		if (current_status[button] == status)
			continue;
		else
			current_status[button] = status;

		dev_dbg(rmi4_data->pdev->dev.parent,
				"%s: Button %d (code %d) ->%d\n",
				__func__, button,
				f1a->button_map[button],
				status);
#ifdef NO_0D_WHILE_2D
		if (rmi4_data->fingers_on_2d == false) {
			if (status == 1) {
				before_2d_status[button] = 1;
			} else {
				if (while_2d_status[button] == 1) {
					while_2d_status[button] = 0;
					continue;
				} else {
					before_2d_status[button] = 0;
				}
			}
			touch_count++;
			input_report_key(rmi4_data->input_dev,
					f1a->button_map[button],
					status);
		} else {
			if (before_2d_status[button] == 1) {
				before_2d_status[button] = 0;
				touch_count++;
				input_report_key(rmi4_data->input_dev,
						f1a->button_map[button],
						status);
			} else {
				if (status == 1)
					while_2d_status[button] = 1;
				else
					while_2d_status[button] = 0;
			}
		}
#else
		touch_count++;
		input_report_key(rmi4_data->input_dev,
				f1a->button_map[button],
				status);
#endif
	}

	if (touch_count)
		input_sync(rmi4_data->input_dev);

	mutex_unlock(&(rmi4_data->rmi4_report_mutex));

	return;
}

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
static void synaptics_rmi4_f54_report(struct synaptics_rmi4_data *rmi4_data)
{
	int ret, size;
	uint8_t data[2] = {0};

	ret = synaptics_rmi4_reg_write(rmi4_data,
			rmi4_data->f54_data_base_addr + REPORT_INDEX_OFFSET,
			data,
			sizeof(data));
	if (ret < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s write error\n",
				__func__);
	} else {
		if (rmi4_data->diag_command == READ_DIFF_DATA ||
				rmi4_data->diag_command == READ_RAW_DATA)
			size = rmi4_data->num_of_tx * rmi4_data->num_of_rx * 2;
		else
			size = (rmi4_data->num_of_tx + rmi4_data->num_of_rx) * 4;

		ret = synaptics_rmi4_reg_read(rmi4_data,
				rmi4_data->f54_data_base_addr + REPORT_DATA_OFFSET,
				rmi4_data->temp_report_data,
				size);

		if (ret >= 0) {
			if (rmi4_data->diag_command == READ_DIFF_DATA ||
					rmi4_data->diag_command == READ_RAW_DATA)
				memcpy(rmi4_data->report_data, rmi4_data->temp_report_data, size);
			else
				memcpy(rmi4_data->report_data_32, rmi4_data->temp_report_data, size);
		} else {
			if (rmi4_data->diag_command == READ_DIFF_DATA ||
					rmi4_data->diag_command == READ_RAW_DATA)
				memset(rmi4_data->report_data, 0x0,
						(4 * rmi4_data->num_of_tx * rmi4_data->num_of_rx));
			else
				memset(rmi4_data->report_data_32, 0x0,
						(4 * (rmi4_data->num_of_tx + rmi4_data->num_of_rx)));
			dev_err(rmi4_data->pdev->dev.parent,
					"%s Read error\n",
					__func__);
		}
	}

	atomic_set(&rmi4_data->data_ready, 1);
	wake_up(&syn_data_ready_wq);
}
#endif

static void synaptics_rmi4_report_touch(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler)
{
	unsigned char touch_count_2d;

	dev_dbg(rmi4_data->pdev->dev.parent,
			"%s: Function %02x reporting\n",
			__func__, fhandler->fn_number);

	switch (fhandler->fn_number) {
	case SYNAPTICS_RMI4_F11:
		touch_count_2d = synaptics_rmi4_f11_abs_report(rmi4_data,
				fhandler);

		if (touch_count_2d)
			rmi4_data->fingers_on_2d = true;
		else
			rmi4_data->fingers_on_2d = false;
		break;
	case SYNAPTICS_RMI4_F12:
		touch_count_2d = synaptics_rmi4_f12_abs_report(rmi4_data,
				fhandler);

		if (touch_count_2d)
			rmi4_data->fingers_on_2d = true;
		else
			rmi4_data->fingers_on_2d = false;
		break;
	case SYNAPTICS_RMI4_F1A:
		synaptics_rmi4_f1a_report(rmi4_data, fhandler);
		break;
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	case SYNAPTICS_RMI4_F54:
		synaptics_rmi4_f54_report(rmi4_data);
		break;
#endif
	case SYNAPTICS_RMI4_F51:
#ifdef USE_DATA_SERVER
		if (synad_pid)
			send_sig_info(SIGIO, &interrupt_signal, synad_task);
#endif
		break;
	default:
		break;
	}

	return;
}

static void synaptics_rmi4_sensor_report(struct synaptics_rmi4_data *rmi4_data,
		bool report)
{
	int retval;
	unsigned char data[MAX_INTR_REGISTERS + 1];
	unsigned char *intr = &data[1];
	bool was_in_bl_mode;
	struct synaptics_rmi4_f01_device_status status;
	struct synaptics_rmi4_fn *fhandler;
	struct synaptics_rmi4_exp_fhandler *exp_fhandler;
	struct synaptics_rmi4_device_info *rmi;

	rmi = &(rmi4_data->rmi4_mod_info);

	/*
	 * Get interrupt status information from F01 Data1 register to
	 * determine the source(s) that are flagging the interrupt.
	 */
	retval = synaptics_rmi4_reg_read(rmi4_data,
			rmi4_data->f01_data_base_addr,
			data,
			rmi4_data->num_of_intr_regs + 1);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to read interrupt status\n",
				__func__);
		return;
	}

	status.data[0] = data[0];
	if (status.status_code == STATUS_CRC_IN_PROGRESS) {
		retval = synaptics_rmi4_check_status(rmi4_data,
				&was_in_bl_mode);
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to check status\n",
					__func__);
			return;
		}
		retval = synaptics_rmi4_reg_read(rmi4_data,
				rmi4_data->f01_data_base_addr,
				status.data,
				sizeof(status.data));
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to read device status\n",
					__func__);
			return;
		}
	}
	if (status.unconfigured && !status.flash_prog) {
		pr_notice("%s: spontaneous reset detected\n", __func__);
		retval = synaptics_rmi4_reinit_device(rmi4_data);
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to reinit device\n",
					__func__);
		}
	}

	if (!report)
		return;

	/*
	 * Traverse the function handler list and service the source(s)
	 * of the interrupt accordingly.
	 */
	if (!list_empty(&rmi->support_fn_list)) {
		list_for_each_entry(fhandler, &rmi->support_fn_list, link) {
			if (fhandler->num_of_data_sources) {
				if (fhandler->intr_mask &
						intr[fhandler->intr_reg_num]) {
					synaptics_rmi4_report_touch(rmi4_data,
							fhandler);
				}
			}
		}
	}

	mutex_lock(&exp_data.mutex);
	if (!list_empty(&exp_data.list)) {
		list_for_each_entry(exp_fhandler, &exp_data.list, link) {
			if (!exp_fhandler->insert &&
					!exp_fhandler->remove &&
					(exp_fhandler->exp_fn->attn != NULL))
				exp_fhandler->exp_fn->attn(rmi4_data, intr[0]);
		}
	}
	mutex_unlock(&exp_data.mutex);

	return;
}

static irqreturn_t synaptics_rmi4_irq(int irq, void *data)
{
	struct synaptics_rmi4_data *rmi4_data = data;
	const struct synaptics_dsx_board_data *bdata =
			rmi4_data->hw_if->board_data;

	if (gpio_get_value(bdata->irq_gpio) != bdata->irq_on_state)
		goto exit;

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	if (debug_mask & BIT(2)) {
		getnstimeofday(&time_start);
	}
#endif

	synaptics_rmi4_sensor_report(rmi4_data, true);

exit:
	return IRQ_HANDLED;
}

static int synaptics_rmi4_int_enable(struct synaptics_rmi4_data *rmi4_data,
		bool enable)
{
	int retval = 0;
	unsigned char ii;
	unsigned char zero = 0x00;
	unsigned char *intr_mask;
	unsigned short intr_addr;

	intr_mask = rmi4_data->intr_mask;

	for (ii = 0; ii < rmi4_data->num_of_intr_regs; ii++) {
		if (intr_mask[ii] != 0x00) {
			intr_addr = rmi4_data->f01_ctrl_base_addr + 1 + ii;
			if (enable) {
				retval = synaptics_rmi4_reg_write(rmi4_data,
						intr_addr,
						&(intr_mask[ii]),
						sizeof(intr_mask[ii]));
				if (retval < 0)
					return retval;
			} else {
				retval = synaptics_rmi4_reg_write(rmi4_data,
						intr_addr,
						&zero,
						sizeof(zero));
				if (retval < 0)
					return retval;
			}
		}
	}

	return retval;
}

static int synaptics_rmi4_irq_enable(struct synaptics_rmi4_data *rmi4_data,
		bool enable, bool attn_only)
{
	int retval = 0;
	unsigned char data[MAX_INTR_REGISTERS];
#if !IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	const struct synaptics_dsx_board_data *bdata =
			rmi4_data->hw_if->board_data;
#endif

	mutex_lock(&(rmi4_data->rmi4_irq_enable_mutex));

	if (attn_only) {
		retval = synaptics_rmi4_int_enable(rmi4_data, enable);
		goto exit;
	}

	if (enable) {
		if (rmi4_data->irq_enabled) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Interrupt already enabled\n",
					__func__);
			goto exit;
		}

		retval = synaptics_rmi4_int_enable(rmi4_data, false);
		if (retval < 0)
			goto exit;

		/* Clear interrupts */
		retval = synaptics_rmi4_reg_read(rmi4_data,
				rmi4_data->f01_data_base_addr + 1,
				data,
				rmi4_data->num_of_intr_regs);
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to read interrupt status\n",
					__func__);
			goto exit;
		}

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
		enable_irq(rmi4_data->irq);
#else
		retval = request_threaded_irq(rmi4_data->irq, NULL,
				synaptics_rmi4_irq, bdata->irq_flags,
				PLATFORM_DRIVER_NAME, rmi4_data);
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to create irq thread\n",
					__func__);
			goto exit;
		}
#endif

		retval = synaptics_rmi4_int_enable(rmi4_data, true);
		if (retval < 0)
			goto exit;

		rmi4_data->irq_enabled = true;
	} else {
		if (rmi4_data->irq_enabled) {
			disable_irq(rmi4_data->irq);
#if !IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
			free_irq(rmi4_data->irq, rmi4_data);
#endif
			rmi4_data->irq_enabled = false;
		}
	}

exit:
	mutex_unlock(&(rmi4_data->rmi4_irq_enable_mutex));

	return retval;
}

static int synaptics_rmi4_set_intr_mask(struct synaptics_rmi4_fn *fhandler,
					struct synaptics_rmi4_fn_desc *fd,
					unsigned int intr_count)
{
	unsigned char ii;
	unsigned char intr_offset;

	fhandler->intr_reg_num = (intr_count + 7) / 8;
	if (fhandler->intr_reg_num >= MAX_INTR_REGISTERS) {
		fhandler->intr_reg_num = 0;
		fhandler->num_of_data_sources = 0;
		fhandler->intr_mask = 0;
		return -EINVAL;
	}
	if (fhandler->intr_reg_num != 0)
		fhandler->intr_reg_num -= 1;

	/* Set an enable bit for each data source */
	intr_offset = intr_count % 8;
	fhandler->intr_mask = 0;
	for (ii = intr_offset;
			ii < (fd->intr_src_count + intr_offset);
			ii++)
		fhandler->intr_mask |= 1 << ii;

	return 0;
}

static int synaptics_rmi4_f01_init(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler,
		struct synaptics_rmi4_fn_desc *fd,
		unsigned int intr_count)
{
	int retval;

	fhandler->fn_number = fd->fn_number;
	fhandler->num_of_data_sources = fd->intr_src_count;
	fhandler->data = NULL;
	fhandler->extra = NULL;

	retval = synaptics_rmi4_set_intr_mask(fhandler, fd, intr_count);
	if (retval < 0)
		return retval;

	rmi4_data->f01_query_base_addr = fd->query_base_addr;
	rmi4_data->f01_ctrl_base_addr = fd->ctrl_base_addr;
	rmi4_data->f01_data_base_addr = fd->data_base_addr;
	rmi4_data->f01_cmd_base_addr = fd->cmd_base_addr;

	return 0;
}

static int synaptics_rmi4_f11_init(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler,
		struct synaptics_rmi4_fn_desc *fd,
		unsigned int intr_count)
{
	int retval;
	int temp;
	unsigned char offset;
	unsigned char fingers_supported;
	struct synaptics_rmi4_f11_extra_data *extra_data;
	struct synaptics_rmi4_f11_query_0_5 query_0_5;
	struct synaptics_rmi4_f11_query_7_8 query_7_8;
	struct synaptics_rmi4_f11_query_9 query_9;
	struct synaptics_rmi4_f11_query_12 query_12;
	struct synaptics_rmi4_f11_query_27 query_27;
	struct synaptics_rmi4_f11_ctrl_6_9 control_6_9;
	const struct synaptics_dsx_board_data *bdata =
				rmi4_data->hw_if->board_data;

	fhandler->fn_number = fd->fn_number;
	fhandler->num_of_data_sources = fd->intr_src_count;
	fhandler->extra = kmalloc(sizeof(*extra_data), GFP_KERNEL);
	if (!fhandler->extra) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for fhandler->extra\n",
				__func__);
		return -ENOMEM;
	}
	extra_data = (struct synaptics_rmi4_f11_extra_data *)fhandler->extra;

	retval = synaptics_rmi4_reg_read(rmi4_data,
			fhandler->full_addr.query_base,
			query_0_5.data,
			sizeof(query_0_5.data));
	if (retval < 0)
		return retval;

	/* Maximum number of fingers supported */
	if (query_0_5.num_of_fingers <= 4)
		fhandler->num_of_data_points = query_0_5.num_of_fingers + 1;
	else if (query_0_5.num_of_fingers == 5)
		fhandler->num_of_data_points = 10;

	rmi4_data->num_of_fingers = fhandler->num_of_data_points;

	retval = synaptics_rmi4_reg_read(rmi4_data,
			fhandler->full_addr.ctrl_base + 6,
			control_6_9.data,
			sizeof(control_6_9.data));
	if (retval < 0)
		return retval;

	/* Maximum x and y */
	rmi4_data->sensor_max_x = control_6_9.sensor_max_x_pos_7_0 |
			(control_6_9.sensor_max_x_pos_11_8 << 8);
	rmi4_data->sensor_max_y = control_6_9.sensor_max_y_pos_7_0 |
			(control_6_9.sensor_max_y_pos_11_8 << 8);
	dev_dbg(rmi4_data->pdev->dev.parent,
			"%s: Function %02x max x = %d max y = %d\n",
			__func__, fhandler->fn_number,
			rmi4_data->sensor_max_x,
			rmi4_data->sensor_max_y);

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	if (bdata->display_width && bdata->display_height
			&& rmi4_data->sensor_max_x && rmi4_data->sensor_max_y) {

		dev_info(rmi4_data->pdev->dev.parent, "%s Load display resolution: %dx%d\n",
				__func__, bdata->display_width, bdata->display_height);
		rmi4_data->width_factor = (bdata->display_width<<SHIFT_BITS)/rmi4_data->sensor_max_x;
		rmi4_data->height_factor = (bdata->display_height<<SHIFT_BITS)/rmi4_data->sensor_max_y;
	}
#endif

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	rmi4_data->max_touch_width = synaptics_sqrt(
			MAX_F11_TOUCH_WIDTH * MAX_F11_TOUCH_WIDTH * 2);
#else
	rmi4_data->max_touch_width = MAX_F11_TOUCH_WIDTH;
#endif

	if (bdata->swap_axes) {
		temp = rmi4_data->sensor_max_x;
		rmi4_data->sensor_max_x = rmi4_data->sensor_max_y;
		rmi4_data->sensor_max_y = temp;
	}

	retval = synaptics_rmi4_set_intr_mask(fhandler, fd, intr_count);
	if (retval < 0)
		return retval;

	fhandler->data = NULL;

	offset = sizeof(query_0_5.data);

	/* query 6 */
	if (query_0_5.has_rel)
		offset += 1;

	/* queries 7 8 */
	if (query_0_5.has_gestures) {
		retval = synaptics_rmi4_reg_read(rmi4_data,
				fhandler->full_addr.query_base + offset,
				query_7_8.data,
				sizeof(query_7_8.data));
		if (retval < 0)
			return retval;

		offset += sizeof(query_7_8.data);
	}

	/* query 9 */
	if (query_0_5.has_query_9) {
		retval = synaptics_rmi4_reg_read(rmi4_data,
				fhandler->full_addr.query_base + offset,
				query_9.data,
				sizeof(query_9.data));
		if (retval < 0)
			return retval;

		offset += sizeof(query_9.data);
	}

	/* query 10 */
	if (query_0_5.has_gestures && query_7_8.has_touch_shapes)
		offset += 1;

	/* query 11 */
	if (query_0_5.has_query_11)
		offset += 1;

	/* query 12 */
	if (query_0_5.has_query_12) {
		retval = synaptics_rmi4_reg_read(rmi4_data,
				fhandler->full_addr.query_base + offset,
				query_12.data,
				sizeof(query_12.data));
		if (retval < 0)
			return retval;

		offset += sizeof(query_12.data);
	}

	/* query 13 */
	if (query_0_5.has_jitter_filter)
		offset += 1;

	/* query 14 */
	if (query_0_5.has_query_12 && query_12.has_general_information_2)
		offset += 1;

	/* queries 15 16 17 18 19 20 21 22 23 24 25 26*/
	if (query_0_5.has_query_12 && query_12.has_physical_properties)
		offset += 12;

	/* query 27 */
	if (query_0_5.has_query_27) {
		retval = synaptics_rmi4_reg_read(rmi4_data,
				fhandler->full_addr.query_base + offset,
				query_27.data,
				sizeof(query_27.data));
		if (retval < 0)
			return retval;

		rmi4_data->f11_wakeup_gesture = query_27.has_wakeup_gesture;
	}

	if (!rmi4_data->f11_wakeup_gesture)
		return retval;

	/* data 0 */
	fingers_supported = fhandler->num_of_data_points;
	offset = (fingers_supported + 3) / 4;

	/* data 1 2 3 4 5 */
	offset += 5 * fingers_supported;

	/* data 6 7 */
	if (query_0_5.has_rel)
		offset += 2 * fingers_supported;

	/* data 8 */
	if (query_0_5.has_gestures && query_7_8.data[0])
		offset += 1;

	/* data 9 */
	if (query_0_5.has_gestures && (query_7_8.data[0] || query_7_8.data[1]))
		offset += 1;

	/* data 10 */
	if (query_0_5.has_gestures &&
			(query_7_8.has_pinch || query_7_8.has_flick))
		offset += 1;

	/* data 11 12 */
	if (query_0_5.has_gestures &&
			(query_7_8.has_flick || query_7_8.has_rotate))
		offset += 2;

	/* data 13 */
	if (query_0_5.has_gestures && query_7_8.has_touch_shapes)
		offset += (fingers_supported + 3) / 4;

	/* data 14 15 */
	if (query_0_5.has_gestures &&
			(query_7_8.has_scroll_zones ||
			query_7_8.has_multi_finger_scroll ||
			query_7_8.has_chiral_scroll))
		offset += 2;

	/* data 16 17 */
	if (query_0_5.has_gestures &&
			(query_7_8.has_scroll_zones &&
			query_7_8.individual_scroll_zones))
		offset += 2;

	/* data 18 19 20 21 22 23 24 25 26 27 */
	if (query_0_5.has_query_9 && query_9.has_contact_geometry)
		offset += 10 * fingers_supported;

	/* data 28 */
	if (query_0_5.has_bending_correction ||
			query_0_5.has_large_object_suppression)
		offset += 1;

	/* data 29 30 31 */
	if (query_0_5.has_query_9 && query_9.has_pen_hover_discrimination)
		offset += 3;

	/* data 32 */
	if (query_0_5.has_query_12 &&
			query_12.has_small_object_detection_tuning)
		offset += 1;

	/* data 33 34 */
	if (query_0_5.has_query_27 && query_27.f11_query27_b0)
		offset += 2;

	/* data 35 */
	if (query_0_5.has_query_12 && query_12.has_8bit_w)
		offset += fingers_supported;

	/* data 36 */
	if (query_0_5.has_bending_correction)
		offset += 1;

	/* data 37 */
	if (query_0_5.has_query_27 && query_27.has_data_37)
		offset += 1;

	/* data 38 */
	if (query_0_5.has_query_27 && query_27.has_wakeup_gesture)
		extra_data->data38_offset = offset;

	return retval;
}

static int synaptics_rmi4_f12_set_enables(struct synaptics_rmi4_data *rmi4_data,
		unsigned short ctrl28)
{
	int retval;
	static unsigned short ctrl_28_address;

	if (ctrl28)
		ctrl_28_address = ctrl28;

	retval = synaptics_rmi4_reg_write(rmi4_data,
			ctrl_28_address,
			&rmi4_data->report_enable,
			sizeof(rmi4_data->report_enable));
	if (retval < 0)
		return retval;

	return retval;
}

static int synaptics_rmi4_f12_find_sub(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler,
		unsigned char *presence, unsigned char presence_size,
		unsigned char structure_offset, unsigned char reg,
		unsigned char sub)
{
	int retval;
	unsigned char cnt;
	unsigned char regnum;
	unsigned char bitnum;
	unsigned char p_index;
	unsigned char s_index;
	unsigned char offset;
	unsigned char max_reg;
	unsigned char *structure;

	max_reg = (presence_size - 1) * 8 - 1;

	if (reg > max_reg) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Register number (%d) over limit\n",
				__func__, reg);
		return -EINVAL;
	}

	p_index = reg / 8 + 1;
	bitnum = reg % 8;
	if ((presence[p_index] & (1 << bitnum)) == 0x00) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Register %d is not present\n",
				__func__, reg);
		return -EINVAL;
	}

	structure = kmalloc(presence[0], GFP_KERNEL);
	if (!structure) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for structure register\n",
				__func__);
		return -ENOMEM;
	}

	retval = synaptics_rmi4_reg_read(rmi4_data,
			fhandler->full_addr.query_base + structure_offset,
			structure,
			presence[0]);
	if (retval < 0)
		goto exit;

	s_index = 0;

	for (regnum = 0; regnum < reg; regnum++) {
		p_index = regnum / 8 + 1;
		bitnum = regnum % 8;
		if ((presence[p_index] & (1 << bitnum)) == 0x00)
			continue;

		if (structure[s_index] == 0x00)
			s_index += 3;
		else
			s_index++;

		while (structure[s_index] & ~MASK_7BIT)
			s_index++;

		s_index++;
	}

	cnt = 0;
	s_index++;
	offset = sub / 7;
	bitnum = sub % 7;

	do {
		if (cnt == offset) {
			if (structure[s_index + cnt] & (1 << bitnum))
				retval = 1;
			else
				retval = 0;
			goto exit;
		}
		cnt++;
	} while (structure[s_index + cnt - 1] & ~MASK_7BIT);

	retval = 0;

exit:
	kfree(structure);

	return retval;
}

static int synaptics_rmi4_configure_long_press_gesture_window(
		struct synaptics_rmi4_data *rmi4_data,
		uint16_t x_min,
		uint16_t x_max,
		uint16_t y_min,
		uint16_t y_max)
{
	uint8_t reg_page;
	uint8_t x_min_lsb = x_min & 0xff;
	uint8_t x_min_msb = x_min >> 8;
	uint8_t x_max_lsb = x_max & 0xff;
	uint8_t x_max_msb = x_max >> 8;
	uint8_t y_min_lsb = y_min & 0xff;
	uint8_t y_min_msb = y_min >> 8;
	uint8_t y_max_lsb = y_max & 0xff;
	uint8_t y_max_msb = y_max >> 8;

#define reg_write_byte_return_if_error(addr, byteptr) \
	do { \
		int ret; \
		ret = synaptics_rmi4_reg_write(rmi4_data, addr, byteptr, 1); \
		if (ret < 0) \
			return ret; \
	} while (0)

#define reg_read_byte_return_if_error(addr, byteptr) \
	do { \
		int ret; \
		ret = synaptics_rmi4_reg_read(rmi4_data, addr, byteptr, 1); \
		if (ret < 0) \
			return ret; \
	} while (0)

	/* switch to register page 4 */
	reg_page = 0x04;
	reg_write_byte_return_if_error(0xff, &reg_page);

	reg_write_byte_return_if_error(0x0b, &x_min_lsb);
	reg_write_byte_return_if_error(0x0c, &x_min_msb);
	reg_write_byte_return_if_error(0x0d, &x_max_lsb);
	reg_write_byte_return_if_error(0x0e, &x_max_msb);
	reg_write_byte_return_if_error(0x0f, &y_min_lsb);
	reg_write_byte_return_if_error(0x10, &y_min_msb);
	reg_write_byte_return_if_error(0x11, &y_max_lsb);
	reg_write_byte_return_if_error(0x12, &y_max_msb);

	/* read back and print config result */
	reg_read_byte_return_if_error(0x0b, &x_min_lsb);
	reg_read_byte_return_if_error(0x0c, &x_min_msb);
	reg_read_byte_return_if_error(0x0d, &x_max_lsb);
	reg_read_byte_return_if_error(0x0e, &x_max_msb);
	reg_read_byte_return_if_error(0x0f, &y_min_lsb);
	reg_read_byte_return_if_error(0x10, &y_min_msb);
	reg_read_byte_return_if_error(0x11, &y_max_lsb);
	reg_read_byte_return_if_error(0x12, &y_max_msb);

	/* reset register page */
	reg_page = 0x00;
	reg_write_byte_return_if_error(0xff, &reg_page);

#undef reg_write_byte_return_if_error
#undef reg_read_byte_return_if_error

	x_min = x_min_msb << 8 | x_min_lsb;
	x_max = x_max_msb << 8 | x_max_lsb;
	y_min = y_min_msb << 8 | y_min_lsb;
	y_max = y_max_msb << 8 | y_max_lsb;
	dev_info(rmi4_data->pdev->dev.parent,
			"%s: long press gesture window [%hu, %hu, %hu, %hu]\n",
			__func__,
			x_min,
			x_max,
			y_min,
			y_max);

	return 0;
}

static int synaptics_rmi4_f12_init(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler,
		struct synaptics_rmi4_fn_desc *fd,
		unsigned int intr_count)
{
	int retval = 0;
	int temp, double_tap[4] = {0};
	unsigned char subpacket;
	unsigned char ctrl_23_size;
	unsigned char size_of_2d_data;
	unsigned char size_of_query5;
	unsigned char size_of_query8;
	unsigned char ctrl_8_offset;
	unsigned char ctrl_18_offset;
	unsigned char ctrl_20_offset;
	unsigned char ctrl_23_offset;
	unsigned char ctrl_27_offset;
	unsigned char ctrl_28_offset;
	unsigned char ctrl_31_offset;
	unsigned char ctrl_58_offset;
	unsigned char num_of_fingers;
	struct synaptics_rmi4_f12_extra_data *extra_data;
	struct synaptics_rmi4_f12_query_5 *query_5 = NULL;
	struct synaptics_rmi4_f12_query_8 *query_8 = NULL;
	struct synaptics_rmi4_f12_ctrl_8 *ctrl_8 = NULL;
	struct synaptics_rmi4_f12_ctrl_18 *ctrl_18 = NULL;
	struct synaptics_rmi4_f12_ctrl_23 *ctrl_23 = NULL;
	struct synaptics_rmi4_f12_ctrl_31 *ctrl_31 = NULL;
	struct synaptics_rmi4_f12_ctrl_58 *ctrl_58 = NULL;
	const struct synaptics_dsx_board_data *bdata =
				rmi4_data->hw_if->board_data;

	fhandler->fn_number = fd->fn_number;
	fhandler->num_of_data_sources = fd->intr_src_count;
	fhandler->extra = kzalloc(sizeof(*extra_data), GFP_KERNEL);
	if (!fhandler->extra) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for fhandler->extra\n",
				__func__);
		return -ENOMEM;
	}
	extra_data = (struct synaptics_rmi4_f12_extra_data *)fhandler->extra;
	size_of_2d_data = sizeof(struct synaptics_rmi4_f12_finger_data);

	query_5 = kzalloc(sizeof(*query_5), GFP_KERNEL);
	if (!query_5) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for query_5\n",
				__func__);
		retval = -ENOMEM;
		goto exit;
	}

	query_8 = kzalloc(sizeof(*query_8), GFP_KERNEL);
	if (!query_8) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for query_8\n",
				__func__);
		retval = -ENOMEM;
		goto exit;
	}

	ctrl_8 = kzalloc(sizeof(*ctrl_8), GFP_KERNEL);
	if (!ctrl_8) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for ctrl_8\n",
				__func__);
		retval = -ENOMEM;
		goto exit;
	}

	ctrl_18 = kzalloc(sizeof(*ctrl_18), GFP_KERNEL);
	if (!ctrl_18) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for ctrl_18\n",
				__func__);
		retval = -ENOMEM;
		goto exit;
	}

	ctrl_23 = kzalloc(sizeof(*ctrl_23), GFP_KERNEL);
	if (!ctrl_23) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for ctrl_23\n",
				__func__);
		retval = -ENOMEM;
		goto exit;
	}

	ctrl_31 = kzalloc(sizeof(*ctrl_31), GFP_KERNEL);
	if (!ctrl_31) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for ctrl_31\n",
				__func__);
		retval = -ENOMEM;
		goto exit;
	}

	ctrl_58 = kzalloc(sizeof(*ctrl_58), GFP_KERNEL);
	if (!ctrl_58) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for ctrl_58\n",
				__func__);
		retval = -ENOMEM;
		goto exit;
	}

	retval = synaptics_rmi4_reg_read(rmi4_data,
			fhandler->full_addr.query_base + 4,
			&size_of_query5,
			sizeof(size_of_query5));
	if (retval < 0)
		goto exit;

	if (size_of_query5 > sizeof(query_5->data))
		size_of_query5 = sizeof(query_5->data);
	memset(query_5->data, 0x00, sizeof(query_5->data));

	retval = synaptics_rmi4_reg_read(rmi4_data,
			fhandler->full_addr.query_base + 5,
			query_5->data,
			size_of_query5);
	if (retval < 0)
		goto exit;

	ctrl_8_offset = query_5->ctrl0_is_present +
			query_5->ctrl1_is_present +
			query_5->ctrl2_is_present +
			query_5->ctrl3_is_present +
			query_5->ctrl4_is_present +
			query_5->ctrl5_is_present +
			query_5->ctrl6_is_present +
			query_5->ctrl7_is_present;

	ctrl_18_offset = ctrl_8_offset +
			query_5->ctrl8_is_present +
			query_5->ctrl9_is_present +
			query_5->ctrl10_is_present +
			query_5->ctrl11_is_present +
			query_5->ctrl12_is_present +
			query_5->ctrl13_is_present +
			query_5->ctrl14_is_present +
			query_5->ctrl15_is_present +
			query_5->ctrl16_is_present +
			query_5->ctrl17_is_present;

	ctrl_20_offset = ctrl_18_offset +
			query_5->ctrl18_is_present +
			query_5->ctrl19_is_present;

	ctrl_23_offset = ctrl_20_offset +
			query_5->ctrl20_is_present +
			query_5->ctrl21_is_present +
			query_5->ctrl22_is_present;

	ctrl_27_offset = ctrl_23_offset +
			query_5->ctrl23_is_present +
			query_5->ctrl24_is_present +
			query_5->ctrl25_is_present +
			query_5->ctrl26_is_present;

	ctrl_28_offset = ctrl_27_offset +
			query_5->ctrl27_is_present;

	ctrl_31_offset = ctrl_28_offset +
			query_5->ctrl28_is_present +
			query_5->ctrl29_is_present +
			query_5->ctrl30_is_present;

	ctrl_58_offset = ctrl_31_offset +
			query_5->ctrl31_is_present +
			query_5->ctrl32_is_present +
			query_5->ctrl33_is_present +
			query_5->ctrl34_is_present +
			query_5->ctrl35_is_present +
			query_5->ctrl36_is_present +
			query_5->ctrl37_is_present +
			query_5->ctrl38_is_present +
			query_5->ctrl39_is_present +
			query_5->ctrl40_is_present +
			query_5->ctrl41_is_present +
			query_5->ctrl42_is_present +
			query_5->ctrl43_is_present +
			query_5->ctrl44_is_present +
			query_5->ctrl45_is_present +
			query_5->ctrl46_is_present +
			query_5->ctrl47_is_present +
			query_5->ctrl48_is_present +
			query_5->ctrl49_is_present +
			query_5->ctrl50_is_present +
			query_5->ctrl51_is_present +
			query_5->ctrl52_is_present +
			query_5->ctrl53_is_present +
			query_5->ctrl54_is_present +
			query_5->ctrl55_is_present +
			query_5->ctrl56_is_present +
			query_5->ctrl57_is_present;

	ctrl_23_size = 2;
	for (subpacket = 2; subpacket <= 4; subpacket++) {
		retval = synaptics_rmi4_f12_find_sub(rmi4_data,
				fhandler, query_5->data, sizeof(query_5->data),
				6, 23, subpacket);
		if (retval == 1)
			ctrl_23_size++;
		else if (retval < 0)
			goto exit;
	}

	retval = synaptics_rmi4_reg_read(rmi4_data,
			fhandler->full_addr.ctrl_base + ctrl_23_offset,
			ctrl_23->data,
			ctrl_23_size);
	if (retval < 0)
		goto exit;

	/* Maximum number of fingers supported */
	fhandler->num_of_data_points = min_t(unsigned char,
			ctrl_23->max_reported_objects,
			(unsigned char)F12_FINGERS_TO_SUPPORT);

	num_of_fingers = fhandler->num_of_data_points;
	rmi4_data->num_of_fingers = num_of_fingers;

	rmi4_data->stylus_enable = ctrl_23->stylus_enable;
	rmi4_data->eraser_enable = ctrl_23->eraser_enable;

	retval = synaptics_rmi4_reg_read(rmi4_data,
			fhandler->full_addr.query_base + 7,
			&size_of_query8,
			sizeof(size_of_query8));
	if (retval < 0)
		goto exit;

	if (size_of_query8 > sizeof(query_8->data))
		size_of_query8 = sizeof(query_8->data);
	memset(query_8->data, 0x00, sizeof(query_8->data));

	retval = synaptics_rmi4_reg_read(rmi4_data,
			fhandler->full_addr.query_base + 8,
			query_8->data,
			size_of_query8);
	if (retval < 0)
		goto exit;

	/* Determine the presence of the Data0 register */
	extra_data->data1_offset = query_8->data0_is_present;

	if ((size_of_query8 >= 3) && (query_8->data15_is_present)) {
		extra_data->data15_offset = query_8->data0_is_present +
				query_8->data1_is_present +
				query_8->data2_is_present +
				query_8->data3_is_present +
				query_8->data4_is_present +
				query_8->data5_is_present +
				query_8->data6_is_present +
				query_8->data7_is_present +
				query_8->data8_is_present +
				query_8->data9_is_present +
				query_8->data10_is_present +
				query_8->data11_is_present +
				query_8->data12_is_present +
				query_8->data13_is_present +
				query_8->data14_is_present;
		extra_data->data15_size = (num_of_fingers + 7) / 8;
	} else {
		extra_data->data15_size = 0;
	}

#ifdef REPORT_2D_PRESSURE
	if ((size_of_query8 >= 5) && (query_8->data29_is_present)) {
		extra_data->data29_offset = query_8->data0_is_present +
				query_8->data1_is_present +
				query_8->data2_is_present +
				query_8->data3_is_present +
				query_8->data4_is_present +
				query_8->data5_is_present +
				query_8->data6_is_present +
				query_8->data7_is_present +
				query_8->data8_is_present +
				query_8->data9_is_present +
				query_8->data10_is_present +
				query_8->data11_is_present +
				query_8->data12_is_present +
				query_8->data13_is_present +
				query_8->data14_is_present +
				query_8->data15_is_present +
				query_8->data16_is_present +
				query_8->data17_is_present +
				query_8->data18_is_present +
				query_8->data19_is_present +
				query_8->data20_is_present +
				query_8->data21_is_present +
				query_8->data22_is_present +
				query_8->data23_is_present +
				query_8->data24_is_present +
				query_8->data25_is_present +
				query_8->data26_is_present +
				query_8->data27_is_present +
				query_8->data28_is_present;
		extra_data->data29_size = 0;
		for (subpacket = 0; subpacket <= num_of_fingers; subpacket++) {
			retval = synaptics_rmi4_f12_find_sub(rmi4_data,
					fhandler, query_8->data,
					sizeof(query_8->data),
					9, 29, subpacket);
			if (retval == 1)
				extra_data->data29_size += 2;
			else if (retval < 0)
				goto exit;
		}
		retval = synaptics_rmi4_reg_read(rmi4_data,
				fhandler->full_addr.ctrl_base + ctrl_58_offset,
				ctrl_58->data,
				sizeof(ctrl_58->data));
		if (retval < 0)
			goto exit;
		rmi4_data->force_min =
				(int)(ctrl_58->min_force_lsb << 0) |
				(int)(ctrl_58->min_force_msb << 8);
		rmi4_data->force_max =
				(int)(ctrl_58->max_force_lsb << 0) |
				(int)(ctrl_58->max_force_msb << 8);
#ifdef TEMP_FORCE_WA
		rmi4_data->force_min = 0;
		rmi4_data->force_max = MAX_F12_TOUCH_PRESSURE;
#endif
		rmi4_data->report_pressure = true;
	} else {
		extra_data->data29_size = 0;
		rmi4_data->force_min = 0;
		rmi4_data->force_max = MAX_F12_TOUCH_PRESSURE;
		rmi4_data->report_pressure = false;
	}
#endif

	rmi4_data->report_enable = RPT_DEFAULT;
#ifdef REPORT_2D_Z
	rmi4_data->report_enable |= RPT_Z;
#endif
#ifdef REPORT_2D_W
	rmi4_data->report_enable |= (RPT_WX | RPT_WY);
#endif

	retval = synaptics_rmi4_f12_set_enables(rmi4_data,
			fhandler->full_addr.ctrl_base + ctrl_28_offset);
	if (retval < 0)
		goto exit;

	if (query_5->ctrl8_is_present) {
		rmi4_data->wedge_sensor = false;

		retval = synaptics_rmi4_reg_read(rmi4_data,
				fhandler->full_addr.ctrl_base + ctrl_8_offset,
				ctrl_8->data,
				sizeof(ctrl_8->data));
		if (retval < 0)
			goto exit;

		/* Maximum x and y */
		rmi4_data->sensor_max_x =
				((unsigned int)ctrl_8->max_x_coord_lsb << 0) |
				((unsigned int)ctrl_8->max_x_coord_msb << 8);
		rmi4_data->sensor_max_y =
				((unsigned int)ctrl_8->max_y_coord_lsb << 0) |
				((unsigned int)ctrl_8->max_y_coord_msb << 8);
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
		rmi4_data->num_of_rx = ctrl_8->num_of_rx;
		rmi4_data->num_of_tx = ctrl_8->num_of_tx;

		rmi4_data->max_touch_width = synaptics_sqrt(
				rmi4_data->num_of_rx*rmi4_data->num_of_rx +
				rmi4_data->num_of_tx*rmi4_data->num_of_tx);
#else
		rmi4_data->max_touch_width = MAX_F12_TOUCH_WIDTH;
#endif
	} else {
		rmi4_data->wedge_sensor = true;

		retval = synaptics_rmi4_reg_read(rmi4_data,
				fhandler->full_addr.ctrl_base + ctrl_31_offset,
				ctrl_31->data,
				sizeof(ctrl_31->data));
		if (retval < 0)
			goto exit;

		/* Maximum x and y */
		rmi4_data->sensor_max_x =
				((unsigned int)ctrl_31->max_x_coord_lsb << 0) |
				((unsigned int)ctrl_31->max_x_coord_msb << 8);
		rmi4_data->sensor_max_y =
				((unsigned int)ctrl_31->max_y_coord_lsb << 0) |
				((unsigned int)ctrl_31->max_y_coord_msb << 8);

		rmi4_data->max_touch_width = MAX_F12_TOUCH_WIDTH;
	}

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	dev_info(rmi4_data->pdev->dev.parent,
			"%s: Function %02x max x = %d max y = %d Rx: %d Tx: %d\n",
			__func__, fhandler->fn_number,
			rmi4_data->sensor_max_x,
			rmi4_data->sensor_max_y,
			rmi4_data->num_of_rx,
			rmi4_data->num_of_tx);
#else
	dev_dbg(rmi4_data->pdev->dev.parent,
			"%s: Function %02x max x = %d max y = %d\n",
			__func__, fhandler->fn_number,
			rmi4_data->sensor_max_x,
			rmi4_data->sensor_max_y);
#endif

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	if (bdata->display_width && bdata->display_height
			&& rmi4_data->sensor_max_x && rmi4_data->sensor_max_y) {
		dev_info(rmi4_data->pdev->dev.parent, "%s Load display resolution: %dx%d\n",
				__func__, bdata->display_width, bdata->display_height);
		rmi4_data->width_factor = (bdata->display_width<<SHIFT_BITS)/rmi4_data->sensor_max_x;
		rmi4_data->height_factor = (bdata->display_height<<SHIFT_BITS)/rmi4_data->sensor_max_y;
	}
#endif

	if (bdata->swap_axes) {
		temp = rmi4_data->sensor_max_x;
		rmi4_data->sensor_max_x = rmi4_data->sensor_max_y;
		rmi4_data->sensor_max_y = temp;
	}

	rmi4_data->f12_wakeup_gesture = query_5->ctrl27_is_present;
	if (rmi4_data->f12_wakeup_gesture) {
		extra_data->ctrl20_offset = ctrl_20_offset;
		extra_data->ctrl27_offset = ctrl_27_offset;
		extra_data->data4_offset = query_8->data0_is_present +
				query_8->data1_is_present +
				query_8->data2_is_present +
				query_8->data3_is_present;

		double_tap[0] = 0;
		double_tap[1] = 0;
		double_tap[2] = bdata->display_width - 1;
		double_tap[3] = bdata->display_height - 1;
		ctrl_18->double_tap_x0_lsb = double_tap[0] & 0xff;
		ctrl_18->double_tap_x0_msb = (double_tap[0] >> 8) & 0xff;
		ctrl_18->double_tap_y0_lsb = double_tap[1] & 0xff;
		ctrl_18->double_tap_y0_msb = (double_tap[1] >> 8) & 0xff;
		ctrl_18->double_tap_x1_lsb = double_tap[2] & 0xff;
		ctrl_18->double_tap_x1_msb = (double_tap[2] >> 8) & 0xff;
		ctrl_18->double_tap_y1_lsb = double_tap[3] & 0xff;
		ctrl_18->double_tap_y1_msb = (double_tap[3] >> 8) & 0xff;

		retval = synaptics_rmi4_reg_write(rmi4_data,
				fhandler->full_addr.ctrl_base + ctrl_18_offset,
				ctrl_18->data,
				sizeof(ctrl_18->data));
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to change double-tap XY setting\n",
					__func__);
			goto exit;
		}

		retval = synaptics_rmi4_reg_read(rmi4_data,
				fhandler->full_addr.ctrl_base + ctrl_18_offset,
				ctrl_18->data,
				sizeof(ctrl_18->data));
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to change double-tap XY settings\n",
					__func__);
			goto exit;
		}

		double_tap[0] = (ctrl_18->double_tap_x0_msb << 8) | ctrl_18->double_tap_x0_lsb;
		double_tap[1] = (ctrl_18->double_tap_y0_msb << 8) | ctrl_18->double_tap_y0_lsb;
		double_tap[2] = (ctrl_18->double_tap_x1_msb << 8) | ctrl_18->double_tap_x1_lsb;
		double_tap[3] = (ctrl_18->double_tap_y1_msb << 8) | ctrl_18->double_tap_y1_lsb;

		printk("[TP]%s:Wakeup Gesture range (%d,%d) -> (%d,%d)\n", __func__,
				double_tap[0], double_tap[1], double_tap[2], double_tap[3]);

		retval = synaptics_rmi4_configure_long_press_gesture_window(
				rmi4_data,
				0,
				bdata->display_width - 1,
				0,
				bdata->display_height - 1);
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: failed to configure long press "
					"gesture window\n",
					__func__);
			goto exit;
		}
	}

	retval = synaptics_rmi4_set_intr_mask(fhandler, fd, intr_count);
	if (retval < 0)
		goto exit;

	/* Allocate memory for finger data storage space */
	fhandler->data_size = num_of_fingers * size_of_2d_data;
	fhandler->data = kmalloc(fhandler->data_size, GFP_KERNEL);
	if (!fhandler->data) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for fhandler->data\n",
				__func__);
		retval = -ENOMEM;
		goto exit;
	}

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	if (rmi4_data->temp_report_data != NULL)
		kfree(rmi4_data->temp_report_data);
	if (rmi4_data->report_data != NULL)
		kfree(rmi4_data->report_data);
	rmi4_data->temp_report_data =
			kzalloc(4 * rmi4_data->num_of_tx * rmi4_data->num_of_rx, GFP_KERNEL);
	rmi4_data->report_data =
			kzalloc(4 * rmi4_data->num_of_tx * rmi4_data->num_of_rx, GFP_KERNEL);
	if(rmi4_data->temp_report_data == NULL || rmi4_data->report_data == NULL) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s report data init fail\n",
				__func__);
		retval = -1;
		goto exit;
	}

	dev_info(rmi4_data->pdev->dev.parent,
			"%s report data init done\n",
			__func__);
#endif

exit:
	kfree(query_5);
	kfree(query_8);
	kfree(ctrl_8);
	kfree(ctrl_18);
	kfree(ctrl_23);
	kfree(ctrl_31);
	kfree(ctrl_58);

	return retval;
}

static int synaptics_rmi4_f1a_alloc_mem(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler)
{
	int retval;
	struct synaptics_rmi4_f1a_handle *f1a;

	f1a = kzalloc(sizeof(*f1a), GFP_KERNEL);
	if (!f1a) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for function handle\n",
				__func__);
		return -ENOMEM;
	}

	fhandler->data = (void *)f1a;
	fhandler->extra = NULL;

	retval = synaptics_rmi4_reg_read(rmi4_data,
			fhandler->full_addr.query_base,
			f1a->button_query.data,
			sizeof(f1a->button_query.data));
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to read query registers\n",
				__func__);
		return retval;
	}

	f1a->max_count = f1a->button_query.max_button_count + 1;

	f1a->button_control.txrx_map = kzalloc(f1a->max_count * 2, GFP_KERNEL);
	if (!f1a->button_control.txrx_map) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for tx rx mapping\n",
				__func__);
		return -ENOMEM;
	}

	f1a->button_bitmask_size = (f1a->max_count + 7) / 8;

	f1a->button_data_buffer = kcalloc(f1a->button_bitmask_size,
			sizeof(*(f1a->button_data_buffer)), GFP_KERNEL);
	if (!f1a->button_data_buffer) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for data buffer\n",
				__func__);
		return -ENOMEM;
	}

	f1a->button_map = kcalloc(f1a->max_count,
			sizeof(*(f1a->button_map)), GFP_KERNEL);
	if (!f1a->button_map) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for button map\n",
				__func__);
		return -ENOMEM;
	}

	return 0;
}

static int synaptics_rmi4_f1a_button_map(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler)
{
	int retval;
	unsigned char ii;
	unsigned char offset = 0;
	struct synaptics_rmi4_f1a_query_4 query_4;
	struct synaptics_rmi4_f1a_handle *f1a = fhandler->data;
	const struct synaptics_dsx_board_data *bdata =
			rmi4_data->hw_if->board_data;

	offset = f1a->button_query.has_general_control +
			f1a->button_query.has_interrupt_enable +
			f1a->button_query.has_multibutton_select;

	if (f1a->button_query.has_tx_rx_map) {
		retval = synaptics_rmi4_reg_read(rmi4_data,
				fhandler->full_addr.ctrl_base + offset,
				f1a->button_control.txrx_map,
				f1a->max_count * 2);
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to read tx rx mapping\n",
					__func__);
			return retval;
		}

		rmi4_data->button_txrx_mapping = f1a->button_control.txrx_map;
	}

	if (f1a->button_query.has_query4) {
		offset = 2 + f1a->button_query.has_query2 +
				f1a->button_query.has_query3;

		retval = synaptics_rmi4_reg_read(rmi4_data,
				fhandler->full_addr.query_base + offset,
				query_4.data,
				sizeof(query_4.data));
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to read button features 4\n",
					__func__);
			return retval;
		}

		if (query_4.has_ctrl24)
			rmi4_data->external_afe_buttons = true;
		else
			rmi4_data->external_afe_buttons = false;
	}

	if (!bdata->cap_button_map) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: cap_button_map is NULL in board file\n",
				__func__);
		return -ENODEV;
	} else if (!bdata->cap_button_map->map) {
		dev_dbg(rmi4_data->pdev->dev.parent,
				"%s: Button map is missing in board file\n",
				__func__);
		return -ENODEV;
	} else {
		if (bdata->cap_button_map->nbuttons != f1a->max_count) {
			f1a->valid_button_count = min(f1a->max_count,
					bdata->cap_button_map->nbuttons);
		} else {
			f1a->valid_button_count = f1a->max_count;
		}

		for (ii = 0; ii < f1a->valid_button_count; ii++)
			f1a->button_map[ii] = bdata->cap_button_map->map[ii];
	}

	return 0;
}

static void synaptics_rmi4_f1a_kfree(struct synaptics_rmi4_fn *fhandler)
{
	struct synaptics_rmi4_f1a_handle *f1a = fhandler->data;

	if (f1a) {
		kfree(f1a->button_control.txrx_map);
		kfree(f1a->button_data_buffer);
		kfree(f1a->button_map);
		kfree(f1a);
		fhandler->data = NULL;
	}

	return;
}

static int synaptics_rmi4_f1a_init(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler,
		struct synaptics_rmi4_fn_desc *fd,
		unsigned int intr_count)
{
	int retval;

	fhandler->fn_number = fd->fn_number;
	fhandler->num_of_data_sources = fd->intr_src_count;

	retval = synaptics_rmi4_set_intr_mask(fhandler, fd, intr_count);
	if (retval < 0)
		goto error_exit;

	retval = synaptics_rmi4_f1a_alloc_mem(rmi4_data, fhandler);
	if (retval < 0)
		goto error_exit;

	retval = synaptics_rmi4_f1a_button_map(rmi4_data, fhandler);
	if (retval < 0)
		goto error_exit;

	rmi4_data->button_0d_enabled = 1;

	return 0;

error_exit:
	synaptics_rmi4_f1a_kfree(fhandler);

	return retval;
}

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
static int synaptics_rmi4_f34_init(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler,
		struct synaptics_rmi4_fn_desc *fd,
		unsigned int intr_count,
		unsigned int page_number)
{
	int retval;

	fhandler->fn_number = fd->fn_number;
	fhandler->num_of_data_sources = fd->intr_src_count;
	fhandler->data = NULL;
	fhandler->extra = NULL;

	retval = synaptics_rmi4_set_intr_mask(fhandler, fd, intr_count);
	if (retval < 0)
		return retval;

	rmi4_data->f34_query_base_addr =
		(fd->query_base_addr | (page_number << 8));
	rmi4_data->f34_ctrl_base_addr =
		(fd->ctrl_base_addr | (page_number << 8));
	rmi4_data->f34_data_base_addr =
		(fd->data_base_addr | (page_number << 8));
	rmi4_data->f34_cmd_base_addr =
		(fd->cmd_base_addr | (page_number << 8));

	return 0;
}

static int synaptics_rmi4_f54_init(struct synaptics_rmi4_data *rmi4_data,
		struct synaptics_rmi4_fn *fhandler,
		struct synaptics_rmi4_fn_desc *fd,
		unsigned int intr_count,
		unsigned int page_number)
{
	struct synaptics_rmi4_f54_query f54_query;
	struct synaptics_rmi4_f54_query_13 query_13;
	struct synaptics_rmi4_f54_query_15 query_15;
	struct synaptics_rmi4_f54_query_16 query_16;
	unsigned char data_offset = REPORT_DATA_OFFSET;
	unsigned char offset;
	int retval;

	fhandler->fn_number = fd->fn_number;
	fhandler->num_of_data_sources = fd->intr_src_count;
	fhandler->data = NULL;
	fhandler->extra = NULL;

	retval = synaptics_rmi4_set_intr_mask(fhandler, fd, intr_count);
	if (retval < 0)
		return retval;

	rmi4_data->f54_query_base_addr =
		(fd->query_base_addr | (page_number << 8));
	rmi4_data->f54_ctrl_base_addr =
		(fd->ctrl_base_addr | (page_number << 8));
	rmi4_data->f54_data_base_addr =
		(fd->data_base_addr | (page_number << 8));
	rmi4_data->f54_cmd_base_addr =
		(fd->cmd_base_addr | (page_number << 8));

	retval = synaptics_rmi4_reg_read(rmi4_data,
			rmi4_data->f54_query_base_addr,
			f54_query.data,
			sizeof(f54_query));
	if (retval < 0)
		return retval;

	offset = sizeof(f54_query.data);

	/* query 12 */
	if (f54_query.has_sense_frequency_control == 0)
		offset -= 1;

	/* query 13 */
	if (f54_query.has_query13) {
		retval = synaptics_rmi4_reg_read(rmi4_data,
				rmi4_data->f54_query_base_addr + offset,
				query_13.data,
				sizeof(query_13.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 14 */
	if (query_13.has_ctrl87)
		offset += 1;

	/* query 15 */
	if (f54_query.has_query15) {
		retval = synaptics_rmi4_reg_read(rmi4_data,
				rmi4_data->f54_query_base_addr + offset,
				query_15.data,
				sizeof(query_15.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* query 16 */
	if (query_15.has_query16) {
		retval = synaptics_rmi4_reg_read(rmi4_data,
				rmi4_data->f54_query_base_addr + offset,
				query_16.data,
				sizeof(query_16.data));
		if (retval < 0)
			return retval;
		offset += 1;
	}

	/* data 4 */
	if (f54_query.has_sense_frequency_control)
		data_offset += 1;

	/* data 5 reserved */

	/* data 6 */
	if (f54_query.has_interference_metric) {
		rmi4_data->f54_im_offset = data_offset + 1;
		data_offset += 2;
	}

	/* data 7.0 */
	if (f54_query.has_two_byte_report_rate |
			f54_query.has_one_byte_report_rate)
		data_offset += 1;

	/* data 7.1 */
	if (f54_query.has_two_byte_report_rate)
		data_offset += 1;

	/* data 8 */
	if (f54_query.has_variance_metric)
		data_offset += 2;

	/* data 9 */
	if (f54_query.has_multi_metric_state_machine)
		data_offset += 2;

	/* data 10 */
	if (f54_query.has_multi_metric_state_machine |
			f54_query.has_noise_state) {
		data_offset += 1;
		rmi4_data->f54_ns_offset = data_offset;
	}

	/* data 11 */
	if (f54_query.has_status)
		data_offset += 1;

	/* data 12 */
	if (f54_query.has_slew_metric)
		data_offset += 2;

	/* data 13 */
	if (f54_query.has_multi_metric_state_machine)
		data_offset += 2;

	/* data 14 */
	if (query_13.has_cidim) {
		data_offset += 1;
		rmi4_data->f54_cidim_offset = data_offset;
	}

	/* data 15 */
	if (query_13.has_rail_im)
		data_offset += 1;

	/* data 16 */
	if (query_13.has_noise_mitigation_enhancement)
		data_offset += 1;

	/* data 17 */
	if (query_16.has_data17) {
		data_offset += 1;
		rmi4_data->f54_freq_offset = data_offset;
	}

	if (rmi4_data->report_data_32 != NULL)
		kfree(rmi4_data->report_data_32);
	rmi4_data->report_data_32 =
			kzalloc(4 * (rmi4_data->num_of_tx + rmi4_data->num_of_rx), GFP_KERNEL);
	if(rmi4_data->report_data_32 == NULL) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s report data 32 init fail\n",
				__func__);
		return -1;
	}

	return 0;
}
#endif

static void synaptics_rmi4_empty_fn_list(struct synaptics_rmi4_data *rmi4_data)
{
	struct synaptics_rmi4_fn *fhandler;
	struct synaptics_rmi4_fn *fhandler_temp;
	struct synaptics_rmi4_device_info *rmi;

	rmi = &(rmi4_data->rmi4_mod_info);

	if (!list_empty(&rmi->support_fn_list)) {
		list_for_each_entry_safe(fhandler,
				fhandler_temp,
				&rmi->support_fn_list,
				link) {
			if (fhandler->fn_number == SYNAPTICS_RMI4_F1A) {
				synaptics_rmi4_f1a_kfree(fhandler);
			} else {
				kfree(fhandler->extra);
				kfree(fhandler->data);
			}
			list_del(&fhandler->link);
			kfree(fhandler);
		}
	}
	INIT_LIST_HEAD(&rmi->support_fn_list);

	return;
}

static int synaptics_rmi4_check_status(struct synaptics_rmi4_data *rmi4_data,
		bool *was_in_bl_mode)
{
	int retval;
	int timeout = CHECK_STATUS_TIMEOUT_MS;
	struct synaptics_rmi4_f01_device_status status;

	retval = synaptics_rmi4_reg_read(rmi4_data,
			rmi4_data->f01_data_base_addr,
			status.data,
			sizeof(status.data));
	if (retval < 0)
		return retval;

	while (status.status_code == STATUS_CRC_IN_PROGRESS) {
		if (timeout > 0)
			msleep(20);
		else
			return -EINVAL;

		retval = synaptics_rmi4_reg_read(rmi4_data,
				rmi4_data->f01_data_base_addr,
				status.data,
				sizeof(status.data));
		if (retval < 0)
			return retval;

		timeout -= 20;
	}

	if (timeout != CHECK_STATUS_TIMEOUT_MS)
		*was_in_bl_mode = true;

	if (status.flash_prog == 1) {
		rmi4_data->flash_prog_mode = true;
		pr_notice("%s: In flash prog mode, status = 0x%02x\n",
				__func__,
				status.status_code);
	} else {
		rmi4_data->flash_prog_mode = false;
	}

	return 0;
}

static void synaptics_rmi4_set_configured(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	unsigned char device_ctrl;

	retval = synaptics_rmi4_reg_read(rmi4_data,
			rmi4_data->f01_ctrl_base_addr,
			&device_ctrl,
			sizeof(device_ctrl));
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to set configured\n",
				__func__);
		return;
	}

	rmi4_data->no_sleep_setting = device_ctrl & NO_SLEEP_ON;
	device_ctrl |= CONFIGURED;

	retval = synaptics_rmi4_reg_write(rmi4_data,
			rmi4_data->f01_ctrl_base_addr,
			&device_ctrl,
			sizeof(device_ctrl));
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to set configured\n",
				__func__);
	}

	return;
}

static int synaptics_rmi4_alloc_fh(struct synaptics_rmi4_fn **fhandler,
		struct synaptics_rmi4_fn_desc *rmi_fd, int page_number)
{
	*fhandler = kzalloc(sizeof(**fhandler), GFP_KERNEL);
	if (!(*fhandler))
		return -ENOMEM;

	(*fhandler)->full_addr.data_base =
			(rmi_fd->data_base_addr |
			(page_number << 8));
	(*fhandler)->full_addr.ctrl_base =
			(rmi_fd->ctrl_base_addr |
			(page_number << 8));
	(*fhandler)->full_addr.cmd_base =
			(rmi_fd->cmd_base_addr |
			(page_number << 8));
	(*fhandler)->full_addr.query_base =
			(rmi_fd->query_base_addr |
			(page_number << 8));

	return 0;
}

static int synaptics_rmi4_query_device(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	unsigned char page_number;
	unsigned char intr_count;
	unsigned char *f01_query;
	unsigned short pdt_entry_addr;
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	uint8_t data[32]={0};
	unsigned char ii;
	unsigned char config_id_size;
	char tmp_buf[5];
#endif
	bool f01found;
	bool f35found;
	bool was_in_bl_mode;
	struct synaptics_rmi4_fn_desc rmi_fd;
	struct synaptics_rmi4_fn *fhandler;
	struct synaptics_rmi4_device_info *rmi;

	rmi = &(rmi4_data->rmi4_mod_info);

rescan_pdt:
	f01found = false;
	f35found = false;
	was_in_bl_mode = false;
	intr_count = 0;
	INIT_LIST_HEAD(&rmi->support_fn_list);

	/* Scan the page description tables of the pages to service */
	for (page_number = 0; page_number < PAGES_TO_SERVICE; page_number++) {
		for (pdt_entry_addr = PDT_START; pdt_entry_addr > PDT_END;
				pdt_entry_addr -= PDT_ENTRY_SIZE) {
			pdt_entry_addr |= (page_number << 8);

			retval = synaptics_rmi4_reg_read(rmi4_data,
					pdt_entry_addr,
					(unsigned char *)&rmi_fd,
					sizeof(rmi_fd));
			if (retval < 0)
				return retval;

			pdt_entry_addr &= ~(MASK_8BIT << 8);

			fhandler = NULL;

			if (rmi_fd.fn_number == 0) {
				dev_dbg(rmi4_data->pdev->dev.parent,
						"%s: Reached end of PDT\n",
						__func__);
				break;
			}

			dev_dbg(rmi4_data->pdev->dev.parent,
					"%s: F%02x found (page %d)\n",
					__func__, rmi_fd.fn_number,
					page_number);

			switch (rmi_fd.fn_number) {
			case SYNAPTICS_RMI4_F01:
				if (rmi_fd.intr_src_count == 0)
					break;

				f01found = true;

				retval = synaptics_rmi4_alloc_fh(&fhandler,
						&rmi_fd, page_number);
				if (retval < 0) {
					dev_err(rmi4_data->pdev->dev.parent,
							"%s: Failed to alloc for F%d\n",
							__func__,
							rmi_fd.fn_number);
					return retval;
				}

				retval = synaptics_rmi4_f01_init(rmi4_data,
						fhandler, &rmi_fd, intr_count);
				if (retval < 0)
					return retval;

				retval = synaptics_rmi4_check_status(rmi4_data,
						&was_in_bl_mode);
				if (retval < 0) {
					dev_err(rmi4_data->pdev->dev.parent,
							"%s: Failed to check status\n",
							__func__);
					return retval;
				}

				if (was_in_bl_mode) {
					kfree(fhandler);
					fhandler = NULL;
					goto rescan_pdt;
				}

				if (rmi4_data->flash_prog_mode)
					goto flash_prog_mode;

				break;
			case SYNAPTICS_RMI4_F11:
				if (rmi_fd.intr_src_count == 0)
					break;

				retval = synaptics_rmi4_alloc_fh(&fhandler,
						&rmi_fd, page_number);
				if (retval < 0) {
					dev_err(rmi4_data->pdev->dev.parent,
							"%s: Failed to alloc for F%d\n",
							__func__,
							rmi_fd.fn_number);
					return retval;
				}

				retval = synaptics_rmi4_f11_init(rmi4_data,
						fhandler, &rmi_fd, intr_count);
				if (retval < 0)
					return retval;
				break;
			case SYNAPTICS_RMI4_F12:
				if (rmi_fd.intr_src_count == 0)
					break;

				retval = synaptics_rmi4_alloc_fh(&fhandler,
						&rmi_fd, page_number);
				if (retval < 0) {
					dev_err(rmi4_data->pdev->dev.parent,
							"%s: Failed to alloc for F%d\n",
							__func__,
							rmi_fd.fn_number);
					return retval;
				}

				retval = synaptics_rmi4_f12_init(rmi4_data,
						fhandler, &rmi_fd, intr_count);
				if (retval < 0)
					return retval;
				break;
			case SYNAPTICS_RMI4_F1A:
				if (rmi_fd.intr_src_count == 0)
					break;

				retval = synaptics_rmi4_alloc_fh(&fhandler,
						&rmi_fd, page_number);
				if (retval < 0) {
					dev_err(rmi4_data->pdev->dev.parent,
							"%s: Failed to alloc for F%d\n",
							__func__,
							rmi_fd.fn_number);
					return retval;
				}

				retval = synaptics_rmi4_f1a_init(rmi4_data,
						fhandler, &rmi_fd, intr_count);
				if (retval < 0) {
#ifdef IGNORE_FN_INIT_FAILURE
					kfree(fhandler);
					fhandler = NULL;
#else
					return retval;
#endif
				}
				break;
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
			case SYNAPTICS_RMI4_F34:
				if (rmi_fd.intr_src_count == 0)
					break;

				retval = synaptics_rmi4_alloc_fh(&fhandler,
						&rmi_fd, page_number);
				if (retval < 0) {
					dev_err(rmi4_data->pdev->dev.parent,
							"%s: Failed to alloc for F%d\n",
							__func__,
							rmi_fd.fn_number);
					return retval;
				}
				retval = synaptics_rmi4_f34_init(rmi4_data,
						fhandler, &rmi_fd, intr_count,page_number);
				if (retval < 0)
					return retval;
				break;
			case SYNAPTICS_RMI4_F54:
				if (rmi_fd.intr_src_count == 0)
					break;

				retval = synaptics_rmi4_alloc_fh(&fhandler,
						&rmi_fd, page_number);
				if (retval < 0) {
					dev_err(rmi4_data->pdev->dev.parent,
							"%s: Failed to alloc for F%d\n",
							__func__,
							rmi_fd.fn_number);
					return retval;
				}
				retval = synaptics_rmi4_f54_init(rmi4_data,
						fhandler, &rmi_fd, intr_count,page_number);
				if (retval < 0)
					return retval;
				break;
#endif
			case SYNAPTICS_RMI4_F35:
				f35found = true;
				break;
			case SYNAPTICS_RMI4_F51:
#ifdef USE_DATA_SERVER
				if (rmi_fd.intr_src_count == 0)
					break;

				retval = synaptics_rmi4_alloc_fh(&fhandler,
						&rmi_fd, page_number);
				if (retval < 0) {
					dev_err(rmi4_data->pdev->dev.parent,
							"%s: Failed to alloc for F%d\n",
							__func__,
							rmi_fd.fn_number);
					return retval;
				}

				fhandler->fn_number = rmi_fd.fn_number;
				fhandler->num_of_data_sources =
						rmi_fd.intr_src_count;
				retval = synaptics_rmi4_set_intr_mask(
						fhandler, &rmi_fd, intr_count);
				if (retval < 0)
					return retval;
#endif

#ifdef F51_DISCRETE_FORCE
				rmi4_data->f51_query_base_addr =
						rmi_fd.query_base_addr |
						(page_number << 8);
#endif
				break;

			}

			/* Accumulate the interrupt count */
			intr_count += rmi_fd.intr_src_count;

			if (fhandler && rmi_fd.intr_src_count) {
				list_add_tail(&fhandler->link,
						&rmi->support_fn_list);
			}
		}
	}

	if (!f01found) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to find F01\n",
				__func__);
		if (!f35found) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to find F35\n",
					__func__);
			return -EINVAL;
		} else {
			pr_notice("%s: In microbootloader mode\n",
					__func__);
			return 0;
		}
	}

flash_prog_mode:
	rmi4_data->num_of_intr_regs = (intr_count + 7) / 8;
	dev_dbg(rmi4_data->pdev->dev.parent,
			"%s: Number of interrupt registers = %d\n",
			__func__, rmi4_data->num_of_intr_regs);
	if (rmi4_data->num_of_intr_regs >= MAX_INTR_REGISTERS)
		return -EINVAL;

	f01_query = kmalloc(F01_STD_QUERY_LEN, GFP_KERNEL);
	if (!f01_query) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to alloc mem for f01_query\n",
				__func__);
		return -ENOMEM;
	}

	retval = synaptics_rmi4_reg_read(rmi4_data,
			rmi4_data->f01_query_base_addr,
			f01_query,
			F01_STD_QUERY_LEN);
	if (retval < 0) {
		kfree(f01_query);
		return retval;
	}

	/* RMI Version 4.0 currently supported */
	rmi->version_major = 4;
	rmi->version_minor = 0;

	rmi->manufacturer_id = f01_query[0];
	rmi->product_props = f01_query[1];
	rmi->product_info[0] = f01_query[2];
	rmi->product_info[1] = f01_query[3];
	retval = secure_memcpy(rmi->product_id_string,
			sizeof(rmi->product_id_string),
			&f01_query[11],
			F01_STD_QUERY_LEN - 11,
			PRODUCT_ID_SIZE);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to copy product ID string\n",
				__func__);
	}

	kfree(f01_query);

	if (rmi->manufacturer_id != 1) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Non-Synaptics device found, manufacturer ID = %d\n",
				__func__, rmi->manufacturer_id);
	}

	retval = synaptics_rmi4_reg_read(rmi4_data,
			rmi4_data->f01_query_base_addr + F01_BUID_ID_OFFSET,
			rmi->build_id,
			sizeof(rmi->build_id));
	if (retval < 0)
		return retval;

	rmi4_data->firmware_id = (unsigned int)rmi->build_id[0] +
			(unsigned int)rmi->build_id[1] * 0x100 +
			(unsigned int)rmi->build_id[2] * 0x10000;

	memset(rmi4_data->intr_mask, 0x00, sizeof(rmi4_data->intr_mask));

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	retval = synaptics_rmi4_reg_read(rmi4_data,
			rmi4_data->f01_query_base_addr + F01_CHIP_ID_OFFSET,
			rmi->package_id,
			sizeof(rmi->package_id));
	if (retval < 0)
		return retval;

	rmi4_data->chip_id = (unsigned int)rmi->package_id[0] +
			(unsigned int)rmi->package_id[1] * 0x100;

	dev_info(rmi4_data->pdev->dev.parent, "%s: chip_id:%d, firmware_id:%d\n",
				__func__, rmi4_data->chip_id, rmi4_data->firmware_id);

	switch (rmi4_data->chip_id) {
	case 3708:
	case 3718:
		config_id_size = V7_CONFIG_ID_SIZE;
		break;
	default:
		config_id_size = V5V6_CONFIG_ID_SIZE;
		break;
	}

	retval = synaptics_rmi4_reg_read(rmi4_data,
			rmi4_data->f34_ctrl_base_addr,
			data,
			sizeof(uint8_t) * config_id_size);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent," %s err r:4\n",__func__);
		return retval;
	}

	memset(rmi4_data->config_version, 0, sizeof(rmi4_data->config_version));
	for (ii = 0; ii < config_id_size; ii++) {
		snprintf(tmp_buf, 3, "%02x ", data[ii]);
		strlcat(rmi4_data->config_version, tmp_buf, sizeof(rmi4_data->config_version));
	}

	dev_info(rmi4_data->pdev->dev.parent,
			"%s: config_version: %s\n",
			__func__,
			rmi4_data->config_version);

	//rmi4_data->config_version = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
	//dev_info(rmi4_data->pdev->dev.parent, "%s config_version: %08X\n", __func__, rmi4_data->config_version);
#endif

	/*
	 * Map out the interrupt bit masks for the interrupt sources
	 * from the registered function handlers.
	 */
	if (!list_empty(&rmi->support_fn_list)) {
		list_for_each_entry(fhandler, &rmi->support_fn_list, link) {
			if (fhandler->num_of_data_sources) {
				rmi4_data->intr_mask[fhandler->intr_reg_num] |=
						fhandler->intr_mask;
			}
		}
	}

	if (rmi4_data->f11_wakeup_gesture || rmi4_data->f12_wakeup_gesture)
		rmi4_data->enable_wakeup_gesture = WAKEUP_GESTURE;
	else
		rmi4_data->enable_wakeup_gesture = false;

	synaptics_rmi4_set_configured(rmi4_data);

	return 0;
}

static int synaptics_rmi4_gpio_setup(int gpio, bool config, int dir, int state)
{
	int retval = 0;
	unsigned char buf[16];

	if (config) {
		snprintf(buf, PAGE_SIZE, "dsx_gpio_%u\n", gpio);

		retval = gpio_request(gpio, buf);
		if (retval) {
			pr_err("%s: Failed to get gpio %d (code: %d)",
					__func__, gpio, retval);
			return retval;
		}

		if (dir == 0)
			retval = gpio_direction_input(gpio);
		else
			retval = gpio_direction_output(gpio, state);
		if (retval) {
			pr_err("%s: Failed to set gpio %d direction",
					__func__, gpio);
			return retval;
		}
	} else {
		gpio_free(gpio);
	}

	return retval;
}

static void synaptics_rmi4_set_params(struct synaptics_rmi4_data *rmi4_data)
{
	unsigned char ii;
	struct synaptics_rmi4_f1a_handle *f1a;
	struct synaptics_rmi4_fn *fhandler;
	struct synaptics_rmi4_device_info *rmi;

	rmi = &(rmi4_data->rmi4_mod_info);

	input_set_abs_params(rmi4_data->input_dev,
			ABS_MT_POSITION_X, 0,
			rmi4_data->sensor_max_x, 0, 0);
	input_set_abs_params(rmi4_data->input_dev,
			ABS_MT_POSITION_Y, 0,
			rmi4_data->sensor_max_y, 0, 0);
#ifdef REPORT_2D_W
	input_set_abs_params(rmi4_data->input_dev,
			ABS_MT_TOUCH_MAJOR, 0,
			rmi4_data->max_touch_width, 0, 0);
	input_set_abs_params(rmi4_data->input_dev,
			ABS_MT_TOUCH_MINOR, 0,
			rmi4_data->max_touch_width, 0, 0);
#endif

#ifdef REPORT_2D_PRESSURE
	input_set_abs_params(rmi4_data->input_dev,
			ABS_MT_PRESSURE, rmi4_data->force_min,
			rmi4_data->force_max, 0, 0);
#elif defined(F51_DISCRETE_FORCE)
	input_set_abs_params(rmi4_data->input_dev,
			ABS_MT_PRESSURE, 0,
			FORCE_LEVEL_MAX, 0, 0);
#endif

#ifdef TYPE_B_PROTOCOL
	if (rmi4_data->input_dev->mt &&
		rmi4_data->input_dev->mt->num_slots != rmi4_data->num_of_fingers)
		input_mt_destroy_slots(rmi4_data->input_dev);
#ifdef KERNEL_ABOVE_3_6
	input_mt_init_slots(rmi4_data->input_dev,
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
			rmi4_data->num_of_fingers, 0);
#else
			rmi4_data->num_of_fingers, INPUT_MT_DIRECT);
#endif
#else
	input_mt_init_slots(rmi4_data->input_dev,
			rmi4_data->num_of_fingers);
#endif
#endif

	f1a = NULL;
	if (!list_empty(&rmi->support_fn_list)) {
		list_for_each_entry(fhandler, &rmi->support_fn_list, link) {
			if (fhandler->fn_number == SYNAPTICS_RMI4_F1A)
				f1a = fhandler->data;
		}
	}

	if (f1a) {
		for (ii = 0; ii < f1a->valid_button_count; ii++) {
			set_bit(f1a->button_map[ii],
					rmi4_data->input_dev->keybit);
			input_set_capability(rmi4_data->input_dev,
					EV_KEY, f1a->button_map[ii]);
		}
	}

	if (vir_button_map->nbuttons) {
		for (ii = 0; ii < vir_button_map->nbuttons; ii++) {
			set_bit(vir_button_map->map[ii * 5],
					rmi4_data->input_dev->keybit);
			input_set_capability(rmi4_data->input_dev,
					EV_KEY, vir_button_map->map[ii * 5]);
		}
	}

	if (rmi4_data->f11_wakeup_gesture || rmi4_data->f12_wakeup_gesture) {
		set_bit(KEY_WAKEUP, rmi4_data->input_dev->keybit);
		input_set_capability(rmi4_data->input_dev, EV_KEY, KEY_WAKEUP);
	}

	return;
}

static int synaptics_rmi4_set_input_dev(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	const struct synaptics_dsx_board_data *bdata =
				rmi4_data->hw_if->board_data;

	rmi4_data->input_dev = input_allocate_device();
	if (rmi4_data->input_dev == NULL) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to allocate input device\n",
				__func__);
		retval = -ENOMEM;
		goto err_input_device;
	}

	retval = synaptics_rmi4_query_device(rmi4_data);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to query device\n",
				__func__);
		goto err_query_device;
	}

	rmi4_data->input_dev->name = PLATFORM_DRIVER_NAME;
	rmi4_data->input_dev->phys = INPUT_PHYS_NAME;
	rmi4_data->input_dev->id.product = SYNAPTICS_DSX_DRIVER_PRODUCT;
	rmi4_data->input_dev->id.version = SYNAPTICS_DSX_DRIVER_VERSION;
	rmi4_data->input_dev->dev.parent = rmi4_data->pdev->dev.parent;
	input_set_drvdata(rmi4_data->input_dev, rmi4_data);

	set_bit(EV_SYN, rmi4_data->input_dev->evbit);
	set_bit(EV_KEY, rmi4_data->input_dev->evbit);
	set_bit(EV_ABS, rmi4_data->input_dev->evbit);
#if !IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	set_bit(BTN_TOUCH, rmi4_data->input_dev->keybit);
	set_bit(BTN_TOOL_FINGER, rmi4_data->input_dev->keybit);
#endif
#ifdef INPUT_PROP_DIRECT
	set_bit(INPUT_PROP_DIRECT, rmi4_data->input_dev->propbit);
#endif

	if (bdata->max_y_for_2d >= 0)
		rmi4_data->sensor_max_y = bdata->max_y_for_2d;

	synaptics_rmi4_set_params(rmi4_data);

	retval = input_register_device(rmi4_data->input_dev);
	if (retval) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to register input device\n",
				__func__);
		goto err_register_input;
	}

	if (!rmi4_data->stylus_enable)
		return 0;

	rmi4_data->stylus_dev = input_allocate_device();
	if (rmi4_data->stylus_dev == NULL) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to allocate stylus device\n",
				__func__);
		retval = -ENOMEM;
		goto err_stylus_device;
	}

	rmi4_data->stylus_dev->name = STYLUS_DRIVER_NAME;
	rmi4_data->stylus_dev->phys = STYLUS_PHYS_NAME;
	rmi4_data->stylus_dev->id.product = SYNAPTICS_DSX_DRIVER_PRODUCT;
	rmi4_data->stylus_dev->id.version = SYNAPTICS_DSX_DRIVER_VERSION;
	rmi4_data->stylus_dev->dev.parent = rmi4_data->pdev->dev.parent;
	input_set_drvdata(rmi4_data->stylus_dev, rmi4_data);

	set_bit(EV_KEY, rmi4_data->stylus_dev->evbit);
	set_bit(EV_ABS, rmi4_data->stylus_dev->evbit);
	set_bit(BTN_TOUCH, rmi4_data->stylus_dev->keybit);
	set_bit(BTN_TOOL_PEN, rmi4_data->stylus_dev->keybit);
	if (rmi4_data->eraser_enable)
		set_bit(BTN_TOOL_RUBBER, rmi4_data->stylus_dev->keybit);
#ifdef INPUT_PROP_DIRECT
	set_bit(INPUT_PROP_DIRECT, rmi4_data->stylus_dev->propbit);
#endif
	input_set_abs_params(rmi4_data->stylus_dev, ABS_X, 0,
			rmi4_data->sensor_max_x, 0, 0);
	input_set_abs_params(rmi4_data->stylus_dev, ABS_Y, 0,
			rmi4_data->sensor_max_y, 0, 0);

	retval = input_register_device(rmi4_data->stylus_dev);
	if (retval) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to register stylus device\n",
				__func__);
		goto err_register_stylus;
	}

	return 0;

err_register_stylus:
	rmi4_data->stylus_dev = NULL;

err_stylus_device:
	input_unregister_device(rmi4_data->input_dev);
	rmi4_data->input_dev = NULL;

err_register_input:
err_query_device:
	synaptics_rmi4_empty_fn_list(rmi4_data);
	input_free_device(rmi4_data->input_dev);

err_input_device:
	return retval;
}

static int synaptics_dsx_pinctrl_init(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;

	/* Get pinctrl if target uses pinctrl */
	rmi4_data->ts_pinctrl = devm_pinctrl_get((rmi4_data->pdev->dev.parent));
	if (IS_ERR_OR_NULL(rmi4_data->ts_pinctrl)) {
		dev_info(rmi4_data->pdev->dev.parent,
			"Target does not use pinctrl\n");
		retval = PTR_ERR(rmi4_data->ts_pinctrl);
		rmi4_data->ts_pinctrl = NULL;
		return retval;
	}

	rmi4_data->gpio_state_active
		= pinctrl_lookup_state(rmi4_data->ts_pinctrl, "pmx_ts_active");
	if (IS_ERR_OR_NULL(rmi4_data->gpio_state_active)) {
		dev_dbg(rmi4_data->pdev->dev.parent,
			"Can not get ts default pinstate\n");
		retval = PTR_ERR(rmi4_data->gpio_state_active);
		rmi4_data->ts_pinctrl = NULL;
		return retval;
	}

	rmi4_data->gpio_state_suspend
		= pinctrl_lookup_state(rmi4_data->ts_pinctrl, "pmx_ts_suspend");
	if (IS_ERR_OR_NULL(rmi4_data->gpio_state_suspend)) {
		dev_dbg(rmi4_data->pdev->dev.parent,
			"Can not get ts sleep pinstate\n");
		retval = PTR_ERR(rmi4_data->gpio_state_suspend);
		rmi4_data->ts_pinctrl = NULL;
		return retval;
	}

	return 0;
}

static void synaptics_dsx_pinctrl_deinit(struct synaptics_rmi4_data *rmi4_data)
{
	/* Put pinctrl if target uses pinctrl */
	if (rmi4_data->ts_pinctrl != NULL) {
		rmi4_data->gpio_state_active = NULL;
		rmi4_data->gpio_state_suspend = NULL;
		devm_pinctrl_put(rmi4_data->ts_pinctrl);
	}
}

static int synaptics_dsx_pinctrl_select(struct synaptics_rmi4_data *rmi4_data,
						bool on)
{
	struct pinctrl_state *pins_state;
	int ret;

	pins_state = on ? rmi4_data->gpio_state_active
		: rmi4_data->gpio_state_suspend;
	if (!IS_ERR_OR_NULL(pins_state)) {
		ret = pinctrl_select_state(rmi4_data->ts_pinctrl, pins_state);
		if (ret) {
			dev_info(rmi4_data->pdev->dev.parent,
				"can not set %s pins\n",
				on ? "pmx_ts_active" : "pmx_ts_suspend");
			return ret;
		}
	} else
		dev_err(rmi4_data->pdev->dev.parent,
			"not a valid '%s' pinstate\n",
				on ? "pmx_ts_active" : "pmx_ts_suspend");

	return 0;
}

static int synaptics_rmi4_set_gpio(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	const struct synaptics_dsx_board_data *bdata =
			rmi4_data->hw_if->board_data;

	retval = synaptics_rmi4_gpio_setup(
			bdata->irq_gpio,
			true, 0, 0);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to configure attention GPIO\n",
				__func__);
		goto err_gpio_irq;
	}

	if (bdata->power_gpio >= 0) {
		retval = synaptics_rmi4_gpio_setup(
				bdata->power_gpio,
				true, 1, !bdata->power_on_state);
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to configure power GPIO\n",
					__func__);
			goto err_gpio_power;
		}
	}

	if (bdata->reset_gpio >= 0) {
		retval = synaptics_rmi4_gpio_setup(
				bdata->reset_gpio,
				true, 1, !bdata->reset_on_state);
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to configure reset GPIO\n",
					__func__);
			goto err_gpio_reset;
		}
	}

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	if (bdata->switch_gpio >= 0) {
		retval = synaptics_rmi4_gpio_setup(
				bdata->switch_gpio,
				true, 1, 0);
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to configure switch GPIO\n",
					__func__);
			goto err_gpio_switch;
		}
	}
#endif

	if (bdata->power_gpio >= 0) {
		gpio_set_value(bdata->power_gpio, bdata->power_on_state);
		msleep(bdata->power_delay_ms);
	}

	if (bdata->reset_gpio >= 0) {
		gpio_set_value(bdata->reset_gpio, bdata->reset_on_state);
		msleep(bdata->reset_active_ms);
		gpio_set_value(bdata->reset_gpio, !bdata->reset_on_state);
		msleep(bdata->reset_delay_ms);
	}

	return 0;

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
err_gpio_switch:
	if (bdata->switch_gpio >= 0)
		synaptics_rmi4_gpio_setup(bdata->switch_gpio, false, 0, 0);
#endif

err_gpio_reset:
	if (bdata->power_gpio >= 0)
		synaptics_rmi4_gpio_setup(bdata->power_gpio, false, 0, 0);

err_gpio_power:
	synaptics_rmi4_gpio_setup(bdata->irq_gpio, false, 0, 0);

err_gpio_irq:
	return retval;
}

static int synaptics_rmi4_get_reg(struct synaptics_rmi4_data *rmi4_data,
		bool get)
{
	int retval;
	const struct synaptics_dsx_board_data *bdata =
			rmi4_data->hw_if->board_data;

	if (!get) {
		retval = 0;
		goto regulator_put;
	}

	if ((bdata->pwr_reg_name != NULL) && (*bdata->pwr_reg_name != 0)) {
		rmi4_data->pwr_reg = regulator_get(rmi4_data->pdev->dev.parent,
				bdata->pwr_reg_name);
		if (IS_ERR(rmi4_data->pwr_reg)) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to get power regulator\n",
					__func__);
			retval = PTR_ERR(rmi4_data->pwr_reg);
			goto regulator_put;
		}
	}

	if ((bdata->bus_reg_name != NULL) && (*bdata->bus_reg_name != 0)) {
		rmi4_data->bus_reg = regulator_get(rmi4_data->pdev->dev.parent,
				bdata->bus_reg_name);
		if (IS_ERR(rmi4_data->bus_reg)) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to get bus pullup regulator\n",
					__func__);
			retval = PTR_ERR(rmi4_data->bus_reg);
			goto regulator_put;
		}
	}

	return 0;

regulator_put:
	if (rmi4_data->pwr_reg) {
		regulator_put(rmi4_data->pwr_reg);
		rmi4_data->pwr_reg = NULL;
	}

	if (rmi4_data->bus_reg) {
		regulator_put(rmi4_data->bus_reg);
		rmi4_data->bus_reg = NULL;
	}

	return retval;
}

static int synaptics_rmi4_enable_reg(struct synaptics_rmi4_data *rmi4_data,
		bool enable)
{
	int retval;
	const struct synaptics_dsx_board_data *bdata =
			rmi4_data->hw_if->board_data;

	if (!enable) {
		retval = 0;
		goto disable_pwr_reg;
	}

	if (rmi4_data->bus_reg) {
		retval = regulator_enable(rmi4_data->bus_reg);
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to enable bus pullup regulator\n",
					__func__);
			goto exit;
		}
	}

	if (rmi4_data->pwr_reg) {
		retval = regulator_enable(rmi4_data->pwr_reg);
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to enable power regulator\n",
					__func__);
			goto disable_bus_reg;
		}
		msleep(bdata->power_delay_ms);
	}

	return 0;

disable_pwr_reg:
	if (rmi4_data->pwr_reg)
		regulator_disable(rmi4_data->pwr_reg);

disable_bus_reg:
	if (rmi4_data->bus_reg)
		regulator_disable(rmi4_data->bus_reg);

exit:
	return retval;
}

static int synaptics_rmi4_free_fingers(struct synaptics_rmi4_data *rmi4_data)
{
	unsigned char ii;

	mutex_lock(&(rmi4_data->rmi4_report_mutex));

#ifdef TYPE_B_PROTOCOL
	for (ii = 0; ii < rmi4_data->num_of_fingers; ii++) {
		input_mt_slot(rmi4_data->input_dev, ii);
		input_mt_report_slot_state(rmi4_data->input_dev,
				MT_TOOL_FINGER, 0);
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
		if (debug_mask & BIT(3))
			rmi4_data->report_points[ii].state = 0;
#endif
	}
#endif
#if !IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	input_report_key(rmi4_data->input_dev,
			BTN_TOUCH, 0);
	input_report_key(rmi4_data->input_dev,
			BTN_TOOL_FINGER, 0);
#endif
#ifndef TYPE_B_PROTOCOL
	input_mt_sync(rmi4_data->input_dev);
#endif
	input_sync(rmi4_data->input_dev);

	if (rmi4_data->stylus_enable) {
		input_report_key(rmi4_data->stylus_dev,
				BTN_TOUCH, 0);
		input_report_key(rmi4_data->stylus_dev,
				BTN_TOOL_PEN, 0);
		if (rmi4_data->eraser_enable) {
			input_report_key(rmi4_data->stylus_dev,
					BTN_TOOL_RUBBER, 0);
		}
		input_sync(rmi4_data->stylus_dev);
	}

	mutex_unlock(&(rmi4_data->rmi4_report_mutex));

	rmi4_data->fingers_on_2d = false;

	return 0;
}

static int synaptics_rmi4_force_cal(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	unsigned char command = 0x02;

	retval = synaptics_rmi4_reg_write(rmi4_data,
			rmi4_data->f54_cmd_base_addr,
			&command,
			sizeof(command));
	 if (retval < 0)
		 return retval;

	 return 0;
}
static int synaptics_rmi4_sw_reset(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	unsigned char command = 0x01;

	retval = synaptics_rmi4_reg_write(rmi4_data,
			rmi4_data->f01_cmd_base_addr,
			&command,
			sizeof(command));
	if (retval < 0)
		return retval;

	msleep(rmi4_data->hw_if->board_data->reset_delay_ms);

	if (rmi4_data->hw_if->ui_hw_init) {
		retval = rmi4_data->hw_if->ui_hw_init(rmi4_data);
		if (retval < 0)
			return retval;
	}

	return 0;
}

static void synaptics_rmi4_rebuild_work(struct work_struct *work)
{
	int retval;
	unsigned char attr_count;
	struct synaptics_rmi4_exp_fhandler *exp_fhandler;
	struct delayed_work *delayed_work =
			container_of(work, struct delayed_work, work);
	struct synaptics_rmi4_data *rmi4_data =
			container_of(delayed_work, struct synaptics_rmi4_data,
			rb_work);

	mutex_lock(&(rmi4_data->rmi4_reset_mutex));

	mutex_lock(&exp_data.mutex);

	synaptics_rmi4_irq_enable(rmi4_data, false, false);

	if (!list_empty(&exp_data.list)) {
		list_for_each_entry(exp_fhandler, &exp_data.list, link)
			if (exp_fhandler->exp_fn->remove != NULL)
				exp_fhandler->exp_fn->remove(rmi4_data);
	}

	for (attr_count = 0; attr_count < ARRAY_SIZE(attrs); attr_count++) {
		sysfs_remove_file(&rmi4_data->input_dev->dev.kobj,
				&attrs[attr_count].attr);
	}

	synaptics_rmi4_free_fingers(rmi4_data);
	synaptics_rmi4_empty_fn_list(rmi4_data);
	input_unregister_device(rmi4_data->input_dev);
	rmi4_data->input_dev = NULL;
	if (rmi4_data->stylus_enable) {
		input_unregister_device(rmi4_data->stylus_dev);
		rmi4_data->stylus_dev = NULL;
	}

	retval = synaptics_rmi4_sw_reset(rmi4_data);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to issue reset command\n",
				__func__);
		goto exit;
	}

	retval = synaptics_rmi4_set_input_dev(rmi4_data);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to set up input device\n",
				__func__);
		goto exit;
	}

	for (attr_count = 0; attr_count < ARRAY_SIZE(attrs); attr_count++) {
		retval = sysfs_create_file(&rmi4_data->input_dev->dev.kobj,
				&attrs[attr_count].attr);
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to create sysfs attributes\n",
					__func__);
			goto exit;
		}
	}

	if (!list_empty(&exp_data.list)) {
		list_for_each_entry(exp_fhandler, &exp_data.list, link)
			if (exp_fhandler->exp_fn->init != NULL)
				exp_fhandler->exp_fn->init(rmi4_data);
	}

	retval = 0;

exit:
	synaptics_rmi4_irq_enable(rmi4_data, true, false);

	mutex_unlock(&exp_data.mutex);

	mutex_unlock(&(rmi4_data->rmi4_reset_mutex));

	return;
}

static int synaptics_rmi4_hw_reset(struct synaptics_rmi4_data *rmi4_data)
{
	const struct synaptics_dsx_board_data *bdata =
			rmi4_data->hw_if->board_data;
	int retval;

	if (bdata->reset_gpio >= 0) {
		gpio_set_value(bdata->reset_gpio, bdata->reset_on_state);
		msleep(bdata->reset_active_ms);
		gpio_set_value(bdata->reset_gpio, !bdata->reset_on_state);
	}

	if (rmi4_data->hw_if->ui_hw_init) {
		retval = rmi4_data->hw_if->ui_hw_init(rmi4_data);
		if (retval < 0)
			return retval;
	}

	return 0;
}

static int synaptics_rmi4_reinit_device(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;
	struct synaptics_rmi4_fn *fhandler;
	struct synaptics_rmi4_exp_fhandler *exp_fhandler;
	struct synaptics_rmi4_device_info *rmi;

	rmi = &(rmi4_data->rmi4_mod_info);

	mutex_lock(&(rmi4_data->rmi4_reset_mutex));

	synaptics_rmi4_free_fingers(rmi4_data);

	if (!list_empty(&rmi->support_fn_list)) {
		list_for_each_entry(fhandler, &rmi->support_fn_list, link) {
			if (fhandler->fn_number == SYNAPTICS_RMI4_F12) {
				synaptics_rmi4_f12_set_enables(rmi4_data, 0);
				break;
			}
		}
	}

	retval = synaptics_rmi4_int_enable(rmi4_data, true);
	if (retval < 0)
		goto exit;

	mutex_lock(&exp_data.mutex);
	if (!list_empty(&exp_data.list)) {
		list_for_each_entry(exp_fhandler, &exp_data.list, link)
			if (exp_fhandler->exp_fn->reinit != NULL)
				exp_fhandler->exp_fn->reinit(rmi4_data);
	}
	mutex_unlock(&exp_data.mutex);

	synaptics_rmi4_set_configured(rmi4_data);

	retval = 0;

exit:
	mutex_unlock(&(rmi4_data->rmi4_reset_mutex));
	return retval;
}

static int synaptics_rmi4_hw_reset_device(struct synaptics_rmi4_data *rmi4_data)
{
	int retval;

	pr_info("%s from %pS\n", __func__, __builtin_return_address(0));

	retval = synaptics_rmi4_hw_reset(rmi4_data);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to issue reset command\n",
				__func__);
		return retval;
	}

	return 0;
}

static int synaptics_rmi4_reset_device(struct synaptics_rmi4_data *rmi4_data,
		bool rebuild)
{
	int retval;
	struct synaptics_rmi4_exp_fhandler *exp_fhandler;

	pr_info("%s from %pS, rebuild = %d\n", __func__, __builtin_return_address(0), rebuild);

	if (rebuild) {
		queue_delayed_work(rmi4_data->rb_workqueue,
				&rmi4_data->rb_work,
				msecs_to_jiffies(REBUILD_WORK_DELAY_MS));
		return 0;
	}

	mutex_lock(&(rmi4_data->rmi4_reset_mutex));

	synaptics_rmi4_irq_enable(rmi4_data, false, false);

	retval = synaptics_rmi4_sw_reset(rmi4_data);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to issue reset command\n",
				__func__);
		goto exit;
	}

	synaptics_rmi4_free_fingers(rmi4_data);

	synaptics_rmi4_empty_fn_list(rmi4_data);

	retval = synaptics_rmi4_query_device(rmi4_data);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to query device\n",
				__func__);
		goto exit;
	}

	synaptics_rmi4_set_params(rmi4_data);

	mutex_lock(&exp_data.mutex);
	if (!list_empty(&exp_data.list)) {
		list_for_each_entry(exp_fhandler, &exp_data.list, link)
			if (exp_fhandler->exp_fn->reset != NULL)
				exp_fhandler->exp_fn->reset(rmi4_data);
	}
	mutex_unlock(&exp_data.mutex);

	retval = 0;

exit:
	synaptics_rmi4_irq_enable(rmi4_data, true, false);

	mutex_unlock(&(rmi4_data->rmi4_reset_mutex));

	return retval;
}

#ifdef FB_READY_RESET
static void synaptics_rmi4_reset_work(struct work_struct *work)
{
	int retval;
	unsigned int timeout;
	struct synaptics_rmi4_data *rmi4_data =
			container_of(work, struct synaptics_rmi4_data,
			reset_work);

	timeout = FB_READY_TIMEOUT_S * 1000 / FB_READY_WAIT_MS + 1;

	while (!rmi4_data->fb_ready) {
		msleep(FB_READY_WAIT_MS);
		timeout--;
		if (timeout == 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Timed out waiting for FB ready\n",
					__func__);
			return;
		}
	}

	mutex_lock(&rmi4_data->rmi4_exp_init_mutex);

	retval = synaptics_rmi4_reset_device(rmi4_data, false);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to issue reset command\n",
				__func__);
	}

	mutex_unlock(&rmi4_data->rmi4_exp_init_mutex);

	return;
}
#endif

static void synaptics_rmi4_sleep_enable(struct synaptics_rmi4_data *rmi4_data,
		bool enable)
{
	int retval;
	unsigned char device_ctrl;
	unsigned char no_sleep_setting = rmi4_data->no_sleep_setting;

	retval = synaptics_rmi4_reg_read(rmi4_data,
			rmi4_data->f01_ctrl_base_addr,
			&device_ctrl,
			sizeof(device_ctrl));
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to read device control\n",
				__func__);
		return;
	}

	device_ctrl = device_ctrl & ~MASK_3BIT;
	if (enable)
		device_ctrl = device_ctrl | NO_SLEEP_OFF | SENSOR_SLEEP;
	else
		device_ctrl = device_ctrl | no_sleep_setting | NORMAL_OPERATION;

	retval = synaptics_rmi4_reg_write(rmi4_data,
			rmi4_data->f01_ctrl_base_addr,
			&device_ctrl,
			sizeof(device_ctrl));
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to write device control\n",
				__func__);
		return;
	}

	rmi4_data->sensor_sleep = enable;

	return;
}

static void synaptics_rmi4_exp_fn_work(struct work_struct *work)
{
	struct synaptics_rmi4_exp_fhandler *exp_fhandler;
	struct synaptics_rmi4_exp_fhandler *exp_fhandler_temp;
	struct synaptics_rmi4_data *rmi4_data = exp_data.rmi4_data;

	mutex_lock(&rmi4_data->rmi4_exp_init_mutex);
	mutex_lock(&rmi4_data->rmi4_reset_mutex);
	mutex_lock(&exp_data.mutex);
	if (!list_empty(&exp_data.list)) {
		list_for_each_entry_safe(exp_fhandler,
				exp_fhandler_temp,
				&exp_data.list,
				link) {
			if ((exp_fhandler->exp_fn->init != NULL) &&
					exp_fhandler->insert) {
				exp_fhandler->exp_fn->init(rmi4_data);
				exp_fhandler->insert = false;
			} else if ((exp_fhandler->exp_fn->remove != NULL) &&
					exp_fhandler->remove) {
				exp_fhandler->exp_fn->remove(rmi4_data);
				list_del(&exp_fhandler->link);
				kfree(exp_fhandler);
			}
		}
	}
	mutex_unlock(&exp_data.mutex);
	mutex_unlock(&rmi4_data->rmi4_reset_mutex);
	mutex_unlock(&rmi4_data->rmi4_exp_init_mutex);

	return;
}

void synaptics_rmi4_new_function(struct synaptics_rmi4_exp_fn *exp_fn,
		bool insert)
{
	struct synaptics_rmi4_exp_fhandler *exp_fhandler;

	if (!exp_data.initialized) {
		mutex_init(&exp_data.mutex);
		INIT_LIST_HEAD(&exp_data.list);
		exp_data.initialized = true;
	}

	mutex_lock(&exp_data.mutex);
	if (insert) {
		exp_fhandler = kzalloc(sizeof(*exp_fhandler), GFP_KERNEL);
		if (!exp_fhandler) {
			pr_err("%s: Failed to alloc mem for expansion function\n",
					__func__);
			goto exit;
		}
		exp_fhandler->exp_fn = exp_fn;
		exp_fhandler->insert = true;
		exp_fhandler->remove = false;
		list_add_tail(&exp_fhandler->link, &exp_data.list);
	} else if (!list_empty(&exp_data.list)) {
		list_for_each_entry(exp_fhandler, &exp_data.list, link) {
			if (exp_fhandler->exp_fn->fn_type == exp_fn->fn_type) {
				exp_fhandler->insert = false;
				exp_fhandler->remove = true;
				goto exit;
			}
		}
	}

exit:
	mutex_unlock(&exp_data.mutex);

	if (exp_data.queue_work) {
		queue_delayed_work(exp_data.workqueue,
				&exp_data.work,
				msecs_to_jiffies(EXP_FN_WORK_DELAY_MS));
	}

	return;
}
EXPORT_SYMBOL(synaptics_rmi4_new_function);

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
static int check_chip_exist(struct synaptics_rmi4_data *rmi4_data)
{
	unsigned char data;
	int retval;

	retval = synaptics_rmi4_reg_read(rmi4_data,
			(PDT_PROPS-1),
			&data,
			sizeof(data));
	if (retval > 0 && (data == SYNAPTICS_RMI4_F34)) {
		dev_info(rmi4_data->pdev->dev.parent, "%s: Synaptics chip exist\n", __func__);
		return 0;
	}

	return -1;
}
#endif

static int synaptics_rmi4_probe(struct platform_device *pdev)
{
	int retval;
	unsigned char attr_count;
	struct synaptics_rmi4_data *rmi4_data;
	const struct synaptics_dsx_hw_interface *hw_if;
	const struct synaptics_dsx_board_data *bdata;
	hw_if = pdev->dev.platform_data;
	if (!hw_if) {
		dev_err(&pdev->dev,
				"%s: No hardware interface found\n",
				__func__);
		return -EINVAL;
	}

	bdata = hw_if->board_data;
	if (!bdata) {
		dev_err(&pdev->dev,
				"%s: No board data found\n",
				__func__);
		return -EINVAL;
	}

	rmi4_data = kzalloc(sizeof(*rmi4_data), GFP_KERNEL);
	if (!rmi4_data) {
		dev_err(&pdev->dev,
				"%s: Failed to alloc mem for rmi4_data\n",
				__func__);
		return -ENOMEM;
	}

	rmi4_data->pdev = pdev;
	rmi4_data->current_page = MASK_8BIT;
	rmi4_data->hw_if = hw_if;
	rmi4_data->suspend = false;
	rmi4_data->irq_enabled = false;
	rmi4_data->fingers_on_2d = false;

	rmi4_data->reset_device = synaptics_rmi4_reset_device;
	rmi4_data->irq_enable = synaptics_rmi4_irq_enable;
	rmi4_data->sleep_enable = synaptics_rmi4_sleep_enable;
	rmi4_data->report_touch = synaptics_rmi4_report_touch;

	mutex_init(&(rmi4_data->rmi4_reset_mutex));
	mutex_init(&(rmi4_data->rmi4_report_mutex));
	mutex_init(&(rmi4_data->rmi4_io_ctrl_mutex));
	mutex_init(&(rmi4_data->rmi4_exp_init_mutex));
	mutex_init(&(rmi4_data->rmi4_irq_enable_mutex));

	platform_set_drvdata(pdev, rmi4_data);

	vir_button_map = bdata->vir_button_map;

	retval = synaptics_rmi4_get_reg(rmi4_data, true);
	if (retval < 0) {
		dev_err(&pdev->dev,
				"%s: Failed to get regulators\n",
				__func__);
		goto err_get_reg;
	}

	retval = synaptics_rmi4_enable_reg(rmi4_data, true);
	if (retval < 0) {
		dev_err(&pdev->dev,
				"%s: Failed to enable regulators\n",
				__func__);
		goto err_enable_reg;
	}

	retval = synaptics_dsx_pinctrl_init(rmi4_data);
	if (!retval && (rmi4_data->ts_pinctrl != NULL)) {
		retval = synaptics_dsx_pinctrl_select(rmi4_data, true);
		if (retval < 0)
			goto err_config_gpio;
	}

	retval = synaptics_rmi4_set_gpio(rmi4_data);
	if (retval < 0) {
		dev_err(&pdev->dev,
				"%s: Failed to set up GPIO's\n",
				__func__);
		goto err_set_gpio;
	}

	if (hw_if->ui_hw_init) {
		retval = hw_if->ui_hw_init(rmi4_data);
		if (retval < 0) {
			dev_err(&pdev->dev,
					"%s: Failed to initialize hardware interface\n",
					__func__);
			goto err_ui_hw_init;
		}
	}

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	retval = check_chip_exist(rmi4_data);
	if (retval < 0) {
		dev_info(&pdev->dev, "%s: No Synaptics chip\n", __func__);
		goto err_set_input_dev;
	}
#endif

	retval = synaptics_rmi4_set_input_dev(rmi4_data);
	if (retval < 0) {
		dev_err(&pdev->dev,
				"%s: Failed to set up input device\n",
				__func__);
		goto err_set_input_dev;
	}

#ifdef CONFIG_FB
	INIT_WORK(&rmi4_data->pm_work, synaptics_pm_worker);
	rmi4_data->fb_notifier.notifier_call = synaptics_rmi4_fb_notifier_cb;
	retval = fb_register_client(&rmi4_data->fb_notifier);
	if (retval < 0) {
		dev_err(&pdev->dev,
				"%s: Failed to register fb notifier client\n",
				__func__);
	}
#endif

#ifdef USE_EARLYSUSPEND
	rmi4_data->early_suspend.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN + 1;
	rmi4_data->early_suspend.suspend = synaptics_rmi4_early_suspend;
	rmi4_data->early_suspend.resume = synaptics_rmi4_late_resume;
	register_early_suspend(&rmi4_data->early_suspend);
#endif

	if (!exp_data.initialized) {
		mutex_init(&exp_data.mutex);
		INIT_LIST_HEAD(&exp_data.list);
		exp_data.initialized = true;
	}

	/* installing GPIO125 as direct connect in SLPI */
	retval = msm_gpio_install_direct_irq(bdata->irq_gpio, 0, 0);
	if (retval) {
		dev_err(rmi4_data->pdev->dev.parent,
			"%sfailed to install direct irq, ret = %d\n",
			__func__, retval);
		goto err_request_irq;
	}

	rmi4_data->irq =
		platform_get_irq_byname(to_platform_device(pdev->dev.parent),
					"tp_direct_interrupt");

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	retval = request_threaded_irq(rmi4_data->irq, NULL,
			synaptics_rmi4_irq,
			IRQF_TRIGGER_HIGH | IRQF_ONESHOT,
			PLATFORM_DRIVER_NAME,
			rmi4_data);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to create irq thread, err = %d\n",
				__func__, retval);
		goto err_request_irq;
	}

	rmi4_data->irq_enabled = true;

	if (rmi4_data->enable_wakeup_gesture)
		irq_set_irq_wake(rmi4_data->irq, 1);
#endif

	retval = synaptics_rmi4_irq_enable(rmi4_data, true, false);
	if (retval < 0) {
		dev_err(&pdev->dev,
				"%s: Failed to enable attention interrupt\n",
				__func__);
		goto err_enable_irq;
	}

	if (vir_button_map->nbuttons) {
		rmi4_data->board_prop_dir = kobject_create_and_add(
				"board_properties", NULL);
		if (!rmi4_data->board_prop_dir) {
			dev_err(&pdev->dev,
					"%s: Failed to create board_properties directory\n",
					__func__);
			goto err_virtual_buttons;
		} else {
			retval = sysfs_create_file(rmi4_data->board_prop_dir,
					&virtual_key_map_attr.attr);
			if (retval < 0) {
				dev_err(&pdev->dev,
						"%s: Failed to create virtual key map file\n",
						__func__);
				goto err_virtual_buttons;
			}
		}
	}
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	retval = synaptics_rmi4_sysfs_init(rmi4_data, true);
	if (retval < 0) {
		dev_err(&pdev->dev,
				"%s: Failed to create sysfs\n", __func__);
		goto err_sysfs_init;
	}
#endif

	for (attr_count = 0; attr_count < ARRAY_SIZE(attrs); attr_count++) {
		retval = sysfs_create_file(&rmi4_data->input_dev->dev.kobj,
				&attrs[attr_count].attr);
		if (retval < 0) {
			dev_err(&pdev->dev,
					"%s: Failed to create sysfs attributes\n",
					__func__);
			goto err_sysfs;
		}
	}

#ifdef USE_DATA_SERVER
	memset(&interrupt_signal, 0, sizeof(interrupt_signal));
	interrupt_signal.si_signo = SIGIO;
	interrupt_signal.si_code = SI_USER;
#endif

	rmi4_data->rb_workqueue =
			create_singlethread_workqueue("dsx_rebuild_workqueue");
	INIT_DELAYED_WORK(&rmi4_data->rb_work, synaptics_rmi4_rebuild_work);

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	rmi4_data->diag_command = READ_RAW_DATA;
	rmi4_data->noise_state.im_m = 0;
	rmi4_data->noise_state.cidim_m = 0;

	init_waitqueue_head(&syn_data_ready_wq);
#endif
	exp_data.workqueue = create_singlethread_workqueue("dsx_exp_workqueue");
	INIT_DELAYED_WORK(&exp_data.work, synaptics_rmi4_exp_fn_work);
	exp_data.rmi4_data = rmi4_data;
	exp_data.queue_work = true;
	queue_delayed_work(exp_data.workqueue,
			&exp_data.work,
			0);

#ifdef FB_READY_RESET
	rmi4_data->reset_workqueue =
			create_singlethread_workqueue("dsx_reset_workqueue");
	INIT_WORK(&rmi4_data->reset_work, synaptics_rmi4_reset_work);
	queue_work(rmi4_data->reset_workqueue, &rmi4_data->reset_work);
#endif

	return retval;

err_sysfs:
	for (attr_count--; attr_count >= 0; attr_count--) {
		sysfs_remove_file(&rmi4_data->input_dev->dev.kobj,
				&attrs[attr_count].attr);
	}

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
err_sysfs_init:
	synaptics_rmi4_sysfs_init(rmi4_data, false);
#endif

err_virtual_buttons:
	if (rmi4_data->board_prop_dir) {
		sysfs_remove_file(rmi4_data->board_prop_dir,
				&virtual_key_map_attr.attr);
		kobject_put(rmi4_data->board_prop_dir);
	}

	synaptics_rmi4_irq_enable(rmi4_data, false, false);

err_enable_irq:
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	free_irq(rmi4_data->irq, rmi4_data);
err_request_irq:
#endif
#ifdef CONFIG_FB
	fb_unregister_client(&rmi4_data->fb_notifier);
#endif

#ifdef USE_EARLYSUSPEND
	unregister_early_suspend(&rmi4_data->early_suspend);
#endif

	synaptics_rmi4_empty_fn_list(rmi4_data);
	input_unregister_device(rmi4_data->input_dev);
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	if (rmi4_data->temp_report_data != NULL)
		kfree(rmi4_data->temp_report_data);
	if (rmi4_data->report_data != NULL)
		kfree(rmi4_data->report_data);
#endif
	rmi4_data->input_dev = NULL;
	if (rmi4_data->stylus_enable) {
		input_unregister_device(rmi4_data->stylus_dev);
		rmi4_data->stylus_dev = NULL;
	}

err_set_input_dev:
	synaptics_rmi4_gpio_setup(bdata->irq_gpio, false, 0, 0);

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	if (bdata->switch_gpio >= 0)
		synaptics_rmi4_gpio_setup(bdata->switch_gpio, false, 0, 0);
#endif

	if (bdata->reset_gpio >= 0)
		synaptics_rmi4_gpio_setup(bdata->reset_gpio, false, 0, 0);

	if (bdata->power_gpio >= 0)
		synaptics_rmi4_gpio_setup(bdata->power_gpio, false, 0, 0);

err_ui_hw_init:
err_set_gpio:
	synaptics_dsx_pinctrl_deinit(rmi4_data);

err_config_gpio:
	synaptics_rmi4_enable_reg(rmi4_data, false);

err_enable_reg:
	synaptics_rmi4_get_reg(rmi4_data, false);

err_get_reg:
	kfree(rmi4_data);

	return retval;
}

static int synaptics_rmi4_remove(struct platform_device *pdev)
{
	unsigned char attr_count;
	struct synaptics_rmi4_data *rmi4_data = platform_get_drvdata(pdev);
	const struct synaptics_dsx_board_data *bdata =
			rmi4_data->hw_if->board_data;

#ifdef FB_READY_RESET
	cancel_work_sync(&rmi4_data->reset_work);
	flush_workqueue(rmi4_data->reset_workqueue);
	destroy_workqueue(rmi4_data->reset_workqueue);
#endif

	cancel_delayed_work_sync(&exp_data.work);
	flush_workqueue(exp_data.workqueue);
	destroy_workqueue(exp_data.workqueue);

	cancel_delayed_work_sync(&rmi4_data->rb_work);
	flush_workqueue(rmi4_data->rb_workqueue);
	destroy_workqueue(rmi4_data->rb_workqueue);

	for (attr_count = 0; attr_count < ARRAY_SIZE(attrs); attr_count++) {
		sysfs_remove_file(&rmi4_data->input_dev->dev.kobj,
				&attrs[attr_count].attr);
	}

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	synaptics_rmi4_sysfs_init(rmi4_data, false);
#endif

	if (rmi4_data->board_prop_dir) {
		sysfs_remove_file(rmi4_data->board_prop_dir,
				&virtual_key_map_attr.attr);
		kobject_put(rmi4_data->board_prop_dir);
	}

	synaptics_rmi4_irq_enable(rmi4_data, false, false);
#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	free_irq(rmi4_data->irq, rmi4_data);
#endif

#ifdef CONFIG_FB
	fb_unregister_client(&rmi4_data->fb_notifier);
#endif

#ifdef USE_EARLYSUSPEND
	unregister_early_suspend(&rmi4_data->early_suspend);
#endif

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	if (rmi4_data->temp_report_data != NULL)
		kfree(rmi4_data->temp_report_data);
	if (rmi4_data->report_data != NULL)
		kfree(rmi4_data->report_data);
#endif
	synaptics_rmi4_empty_fn_list(rmi4_data);
	input_unregister_device(rmi4_data->input_dev);
	rmi4_data->input_dev = NULL;
	if (rmi4_data->stylus_enable) {
		input_unregister_device(rmi4_data->stylus_dev);
		rmi4_data->stylus_dev = NULL;
	}

	synaptics_rmi4_gpio_setup(bdata->irq_gpio, false, 0, 0);

#if IS_ENABLED(CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC)
	if (bdata->switch_gpio >= 0)
		synaptics_rmi4_gpio_setup(bdata->switch_gpio, false, 0, 0);
#endif

	if (bdata->reset_gpio >= 0)
		synaptics_rmi4_gpio_setup(bdata->reset_gpio, false, 0, 0);

	if (bdata->power_gpio >= 0)
		synaptics_rmi4_gpio_setup(bdata->power_gpio, false, 0, 0);

	synaptics_dsx_pinctrl_deinit(rmi4_data);
	synaptics_rmi4_enable_reg(rmi4_data, false);
	synaptics_rmi4_get_reg(rmi4_data, false);

	kfree(rmi4_data);

	return 0;
}

static void synaptics_rmi4_f11_wg(struct synaptics_rmi4_data *rmi4_data,
		bool enable)
{
	int retval;
	unsigned char reporting_control;
	struct synaptics_rmi4_fn *fhandler;
	struct synaptics_rmi4_device_info *rmi;

	rmi = &(rmi4_data->rmi4_mod_info);

	list_for_each_entry(fhandler, &rmi->support_fn_list, link) {
		if (fhandler->fn_number == SYNAPTICS_RMI4_F11)
			break;
	}

	retval = synaptics_rmi4_reg_read(rmi4_data,
			fhandler->full_addr.ctrl_base,
			&reporting_control,
			sizeof(reporting_control));
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to change reporting mode\n",
				__func__);
		return;
	}

	reporting_control = (reporting_control & ~MASK_3BIT);
	if (enable)
		reporting_control |= F11_WAKEUP_GESTURE_MODE;
	else
		reporting_control |= F11_CONTINUOUS_MODE;

	retval = synaptics_rmi4_reg_write(rmi4_data,
			fhandler->full_addr.ctrl_base,
			&reporting_control,
			sizeof(reporting_control));
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to change reporting mode\n",
				__func__);
		return;
	}

	return;
}

static void synaptics_rmi4_f12_wg(struct synaptics_rmi4_data *rmi4_data,
		bool enable)
{
	int retval;
	unsigned char reporting_control[3];
	struct synaptics_rmi4_f12_ctrl_27 ctrl_27;
	struct synaptics_rmi4_f12_extra_data *extra_data;
	struct synaptics_rmi4_fn *fhandler;
	struct synaptics_rmi4_device_info *rmi;

	rmi = &(rmi4_data->rmi4_mod_info);

	list_for_each_entry(fhandler, &rmi->support_fn_list, link) {
		if (fhandler->fn_number == SYNAPTICS_RMI4_F12)
			break;
	}

	extra_data = (struct synaptics_rmi4_f12_extra_data *)fhandler->extra;

	retval = synaptics_rmi4_reg_read(rmi4_data,
			fhandler->full_addr.ctrl_base +
				extra_data->ctrl20_offset,
			reporting_control,
			sizeof(reporting_control));
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to change reporting mode\n",
				__func__);
		return;
	}

	retval = synaptics_rmi4_reg_read(rmi4_data,
			fhandler->full_addr.ctrl_base +
				extra_data->ctrl27_offset,
			ctrl_27.data,
			sizeof(ctrl_27.data));
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to change lpwg settings\n",
				__func__);
		return;
	}

	if (enable) {
		reporting_control[2] = F12_WAKEUP_GESTURE_MODE;
		ctrl_27.double_tap_enable = 1;
		ctrl_27.lpwg_report_rate = 20;
		ctrl_27.false_activation_threshold = 3;
		ctrl_27.maximum_active_duration = 12;
		ctrl_27.timer_1_duration = 15;
		ctrl_27.maximum_active_duration_timeout = 10;
	} else {
		reporting_control[2] = F12_CONTINUOUS_MODE;
		ctrl_27.double_tap_enable = 0;
		ctrl_27.lpwg_report_rate = 20;
		ctrl_27.false_activation_threshold = 3;
		ctrl_27.maximum_active_duration = 12;
		ctrl_27.timer_1_duration = 15;
		ctrl_27.maximum_active_duration_timeout = 10;
	}

	retval = synaptics_rmi4_reg_write(rmi4_data,
			fhandler->full_addr.ctrl_base +
				extra_data->ctrl27_offset,
			ctrl_27.data,
			sizeof(ctrl_27.data));
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to change lpwg settings\n",
				__func__);
		return;
	}

	retval = synaptics_rmi4_reg_write(rmi4_data,
			fhandler->full_addr.ctrl_base +
				extra_data->ctrl20_offset,
			reporting_control,
			sizeof(reporting_control));
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to change reporting mode\n",
				__func__);
		return;
	}

	return;
}

static void synaptics_rmi4_wakeup_gesture(struct synaptics_rmi4_data *rmi4_data,
		bool enable)
{
	if (rmi4_data->f11_wakeup_gesture)
		synaptics_rmi4_f11_wg(rmi4_data, enable);
	else if (rmi4_data->f12_wakeup_gesture)
		synaptics_rmi4_f12_wg(rmi4_data, enable);

	return;
}

#ifdef CONFIG_FB
static void synaptics_pm_worker(struct work_struct *work)
{
	struct synaptics_rmi4_data *rmi4_data =
			container_of(work, typeof(*rmi4_data), pm_work);

	if (rmi4_data->fb_ready)
		synaptics_rmi4_resume(&rmi4_data->pdev->dev);
	else
		synaptics_rmi4_suspend(&rmi4_data->pdev->dev);
}

static int synaptics_rmi4_fb_notifier_cb(struct notifier_block *self,
		unsigned long event, void *data)
{
	int *transition;
	struct fb_event *evdata = data;
	struct synaptics_rmi4_data *rmi4_data =
			container_of(self, struct synaptics_rmi4_data,
			fb_notifier);

	if (evdata && evdata->data && event == FB_EARLY_EVENT_BLANK) {
		transition = evdata->data;
		dev_info(rmi4_data->pdev->dev.parent, "%s, event = %ld blank = %d\n",
				__func__, event, *transition);
		if ((*transition == FB_BLANK_POWERDOWN ||
		     *transition == FB_BLANK_NORMAL ||
		     *transition == FB_BLANK_VSYNC_SUSPEND) &&
		    rmi4_data->fb_ready) {
			rmi4_data->fb_ready = false;
			schedule_work(&rmi4_data->pm_work);
		} else if (*transition == FB_BLANK_UNBLANK &&
			   !rmi4_data->fb_ready) {
			rmi4_data->fb_ready = true;
			schedule_work(&rmi4_data->pm_work);
		}
	}

	return 0;
}
#endif

#ifdef USE_EARLYSUSPEND
static void synaptics_rmi4_early_suspend(struct early_suspend *h)
{
	struct synaptics_rmi4_exp_fhandler *exp_fhandler;
	struct synaptics_rmi4_data *rmi4_data =
			container_of(h, struct synaptics_rmi4_data,
			early_suspend);

	if (rmi4_data->stay_awake)
		return;

	if (rmi4_data->enable_wakeup_gesture) {
		synaptics_rmi4_wakeup_gesture(rmi4_data, true);
		enable_irq_wake(rmi4_data->irq);
		goto exit;
	}

	synaptics_rmi4_irq_enable(rmi4_data, false, false);
	synaptics_rmi4_sleep_enable(rmi4_data, true);
	synaptics_rmi4_free_fingers(rmi4_data);

exit:
	mutex_lock(&exp_data.mutex);
	if (!list_empty(&exp_data.list)) {
		list_for_each_entry(exp_fhandler, &exp_data.list, link)
			if (exp_fhandler->exp_fn->early_suspend != NULL)
				exp_fhandler->exp_fn->early_suspend(rmi4_data);
	}
	mutex_unlock(&exp_data.mutex);

	rmi4_data->suspend = true;

	return;
}

static void synaptics_rmi4_late_resume(struct early_suspend *h)
{
#ifdef FB_READY_RESET
	int retval;
#endif
	struct synaptics_rmi4_exp_fhandler *exp_fhandler;
	struct synaptics_rmi4_data *rmi4_data =
			container_of(h, struct synaptics_rmi4_data,
			early_suspend);

	if (rmi4_data->stay_awake)
		return;

	if (rmi4_data->enable_wakeup_gesture) {
		synaptics_rmi4_wakeup_gesture(rmi4_data, false);
		disable_irq_wake(rmi4_data->irq);
		goto exit;
	}

	rmi4_data->current_page = MASK_8BIT;

	if (rmi4_data->suspend) {
		synaptics_rmi4_sleep_enable(rmi4_data, false);
		synaptics_rmi4_irq_enable(rmi4_data, true, false);
	}

exit:
#ifdef FB_READY_RESET
	if (rmi4_data->suspend) {
		retval = synaptics_rmi4_reset_device(rmi4_data, false);
		if (retval < 0) {
			dev_err(rmi4_data->pdev->dev.parent,
					"%s: Failed to issue reset command\n",
					__func__);
		}
	}
#endif
	mutex_lock(&exp_data.mutex);
	if (!list_empty(&exp_data.list)) {
		list_for_each_entry(exp_fhandler, &exp_data.list, link)
			if (exp_fhandler->exp_fn->late_resume != NULL)
				exp_fhandler->exp_fn->late_resume(rmi4_data);
	}
	mutex_unlock(&exp_data.mutex);

	rmi4_data->suspend = false;

	return;
}
#endif

static int synaptics_rmi4_suspend(struct device *dev)
{
	struct synaptics_rmi4_exp_fhandler *exp_fhandler;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	if (rmi4_data->stay_awake)
		return 0;

	if (rmi4_data->enable_wakeup_gesture) {
		synaptics_rmi4_wakeup_gesture(rmi4_data, true);
		enable_irq_wake(rmi4_data->irq);
		goto exit;
	}

	if (!rmi4_data->suspend) {
		synaptics_rmi4_irq_enable(rmi4_data, false, false);
		synaptics_rmi4_sleep_enable(rmi4_data, true);
	}

exit:
	mutex_lock(&exp_data.mutex);
	if (!list_empty(&exp_data.list)) {
		list_for_each_entry(exp_fhandler, &exp_data.list, link)
			if (exp_fhandler->exp_fn->suspend != NULL)
				exp_fhandler->exp_fn->suspend(rmi4_data);
	}
	mutex_unlock(&exp_data.mutex);

	gpio_set_value(rmi4_data->hw_if->board_data->switch_gpio, 1);
	dev_dbg(rmi4_data->pdev->dev.parent, "%s: Switch I2C mux to SLPI\n",
			__func__);

	rmi4_data->suspend = true;

	return 0;
}

static int synaptics_rmi4_resume(struct device *dev)
{
#ifdef FB_READY_RESET
	int retval;
#endif
	struct synaptics_rmi4_exp_fhandler *exp_fhandler;
	struct synaptics_rmi4_data *rmi4_data = dev_get_drvdata(dev);

	if (rmi4_data->stay_awake)
		return 0;

	gpio_set_value(rmi4_data->hw_if->board_data->switch_gpio, 0);
	dev_dbg(rmi4_data->pdev->dev.parent, "%s: Switch I2C mux to AP\n",
			__func__);

	synaptics_rmi4_free_fingers(rmi4_data);

	if (rmi4_data->enable_wakeup_gesture) {
		synaptics_rmi4_wakeup_gesture(rmi4_data, false);
		disable_irq_wake(rmi4_data->irq);
		synaptics_rmi4_force_cal(rmi4_data);
		goto exit;
	}

	rmi4_data->current_page = MASK_8BIT;

	synaptics_rmi4_wakeup_gesture(rmi4_data, false);
	synaptics_rmi4_force_cal(rmi4_data);
	synaptics_rmi4_sleep_enable(rmi4_data, false);
	synaptics_rmi4_irq_enable(rmi4_data, true, false);

exit:
#ifdef FB_READY_RESET
	retval = synaptics_rmi4_reset_device(rmi4_data, false);
	if (retval < 0) {
		dev_err(rmi4_data->pdev->dev.parent,
				"%s: Failed to issue reset command\n",
				__func__);
	}
#endif
	mutex_lock(&exp_data.mutex);
	if (!list_empty(&exp_data.list)) {
		list_for_each_entry(exp_fhandler, &exp_data.list, link)
			if (exp_fhandler->exp_fn->resume != NULL)
				exp_fhandler->exp_fn->resume(rmi4_data);
	}
	mutex_unlock(&exp_data.mutex);

	rmi4_data->suspend = false;

	return 0;
}

#ifdef CONFIG_PM
static const struct dev_pm_ops synaptics_rmi4_dev_pm_ops = {
#ifndef CONFIG_FB
	.suspend = synaptics_rmi4_suspend,
	.resume = synaptics_rmi4_resume,
#endif
};
#endif

static struct platform_driver synaptics_rmi4_driver = {
	.driver = {
		.name = PLATFORM_DRIVER_NAME,
		.owner = THIS_MODULE,
#ifdef CONFIG_PM
		.pm = &synaptics_rmi4_dev_pm_ops,
#endif
	},
	.probe = synaptics_rmi4_probe,
	.remove = synaptics_rmi4_remove,
};

static int __init synaptics_rmi4_init(void)
{
	int retval;

	retval = synaptics_rmi4_bus_init_v26();
	if (retval)
		return retval;

	return platform_driver_register(&synaptics_rmi4_driver);
}

static void __exit synaptics_rmi4_exit(void)
{
	platform_driver_unregister(&synaptics_rmi4_driver);

	synaptics_rmi4_bus_exit_v26();

	return;
}

module_init(synaptics_rmi4_init);
module_exit(synaptics_rmi4_exit);

MODULE_AUTHOR("Synaptics, Inc.");
MODULE_DESCRIPTION("Synaptics DSX Touch Driver");
MODULE_LICENSE("GPL v2");
