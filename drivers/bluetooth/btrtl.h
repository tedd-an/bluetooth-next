/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  Bluetooth support for Realtek devices
 *
 *  Copyright (C) 2015 Endless Mobile, Inc.
 */

#define RTL_FRAG_LEN 252

#define rtl_dev_err(dev, fmt, ...) bt_dev_err(dev, "RTL: " fmt, ##__VA_ARGS__)
#define rtl_dev_warn(dev, fmt, ...) bt_dev_warn(dev, "RTL: " fmt, ##__VA_ARGS__)
#define rtl_dev_info(dev, fmt, ...) bt_dev_info(dev, "RTL: " fmt, ##__VA_ARGS__)
#define rtl_dev_dbg(dev, fmt, ...) bt_dev_dbg(dev, "RTL: " fmt, ##__VA_ARGS__)

enum btrtl_chip_id {
	CHIP_ID_8723A,
	CHIP_ID_8723B,
	CHIP_ID_8821A,
	CHIP_ID_8761A,
	CHIP_ID_8822B = 8,
	CHIP_ID_8723D,
	CHIP_ID_8821C,
	CHIP_ID_8822C = 13,
	CHIP_ID_8761B,
	CHIP_ID_8852A = 18,
};

struct id_table {
	__u16 match_flags;
	__u16 lmp_subver;
	__u16 hci_rev;
	__u8 hci_ver;
	__u8 hci_bus;
	bool config_needed;
	bool has_rom_version;
	char *fw_name;
	char *cfg_name;
};

struct btrtl_device_info {
	const struct id_table *ic_info;
	u8 rom_version;
	u8 *fw_data;
	int fw_len;
	u8 *cfg_data;
	int cfg_len;
	bool drop_fw;
	int project_id;
};

struct rtl_download_cmd {
	__u8 index;
	__u8 data[RTL_FRAG_LEN];
} __packed;

struct rtl_download_response {
	__u8 status;
	__u8 index;
} __packed;

struct rtl_rom_version_evt {
	__u8 status;
	__u8 version;
} __packed;

struct rtl_epatch_header {
	__u8 signature[8];
	__le32 fw_version;
	__le16 num_patches;
} __packed;

struct rtl_vendor_config_entry {
	__le16 offset;
	__u8 len;
	__u8 data[];
} __packed;

struct rtl_vendor_config {
	__le32 signature;
	__le16 total_len;
	struct rtl_vendor_config_entry entry[];
} __packed;

#if IS_ENABLED(CONFIG_BT_RTL)

struct btrtl_device_info *btrtl_initialize(struct hci_dev *hdev,
					   const char *postfix);
void btrtl_free(struct btrtl_device_info *btrtl_dev);
int btrtl_download_firmware(struct hci_dev *hdev,
			    struct btrtl_device_info *btrtl_dev);
int btrtl_setup_realtek(struct hci_dev *hdev);
int btrtl_shutdown_realtek(struct hci_dev *hdev);
int btrtl_get_uart_settings(struct hci_dev *hdev,
			    struct btrtl_device_info *btrtl_dev,
			    unsigned int *controller_baudrate,
			    u32 *device_baudrate, bool *flow_control);

#else

static inline struct btrtl_device_info *btrtl_initialize(struct hci_dev *hdev,
							 const char *postfix)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void btrtl_free(struct btrtl_device_info *btrtl_dev)
{
}

static inline int btrtl_download_firmware(struct hci_dev *hdev,
					  struct btrtl_device_info *btrtl_dev)
{
	return -EOPNOTSUPP;
}

static inline int btrtl_setup_realtek(struct hci_dev *hdev)
{
	return -EOPNOTSUPP;
}

static inline int btrtl_shutdown_realtek(struct hci_dev *hdev)
{
	return -EOPNOTSUPP;
}

static inline int btrtl_get_uart_settings(struct hci_dev *hdev,
					  struct btrtl_device_info *btrtl_dev,
					  unsigned int *controller_baudrate,
					  u32 *device_baudrate,
					  bool *flow_control)
{
	return -ENOENT;
}

#endif
