#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <stdbool.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define PARAM_DATA_MAX_LEN	512	/* TODO: Handle larger parameter data sizes */

#define MGMT_EVT_COMMAND_COMPLETE	0x0001
#define MGMT_EVT_COMMAND_STATUS		0x0002

#define OCF_READ_SCO_PCM_INT_PARAM	0x1D

struct __attribute__((__packed__)) mgmt_pkt_hdr {
	uint16_t code;
	uint16_t ctrl_idx;
	uint16_t param_len;
};

struct __attribute__((__packed__)) mgmt_pkt {
	struct mgmt_pkt_hdr hdr;
	uint8_t param_data[PARAM_DATA_MAX_LEN];
};

struct ctrl_info {
	bdaddr_t address;
	uint8_t bluetooth_version;
	uint16_t manufacturer;
	uint32_t supported_settings;
	uint32_t current_settings;
	uint32_t class_of_device;
	char name[249];
	char short_name[11];
};

static struct mgmt_pkt packet;		/* Common global packet used as buffer for reads and writes to management socket */

static int mgmt_write_cmd(int mgmt_fd, struct mgmt_pkt *cmd)
{
	int err;
	size_t bytes_to_write = sizeof(*cmd) - sizeof(cmd->param_data) + cmd->hdr.param_len;

	cmd->hdr.code = htobs(cmd->hdr.code);
	cmd->hdr.ctrl_idx = htobs(cmd->hdr.ctrl_idx);
	cmd->hdr.param_len = htobs(cmd->hdr.param_len);

	if (write(mgmt_fd, cmd, bytes_to_write) != bytes_to_write) {
		printf("ERROR: Write command failed; %s\n", strerror(errno));
		err = EIO;
		goto exit;
	}

	err = 0;
exit:
	return err;
}

static int mgmt_read_evt(int mgmt_fd, struct mgmt_pkt *evt)
{
	int err;
	ssize_t bytes_read;

	bytes_read = read(mgmt_fd, evt, sizeof(*evt));
	if (bytes_read < sizeof(evt->hdr)) {
		printf("ERROR: Read event header failed; %s\n", strerror(errno));
		err = EIO;
		goto exit;
	}

	evt->hdr.code = btohs(evt->hdr.code);
	evt->hdr.ctrl_idx = btohs(evt->hdr.ctrl_idx);
	evt->hdr.param_len = btohs(evt->hdr.param_len);

	if (bytes_read != sizeof(evt->hdr) + evt->hdr.param_len) {
		printf("ERROR: Read event parameters failed; %s\n", strerror(errno));
		err = EIO;
		goto exit;
	}

	err = 0;
exit:
	return err;
}

static int mgmt_send_cmd(int mgmt_fd, struct mgmt_pkt *cmd, uint8_t *status)
{
	int err;
	bool cmd_finished = false;
	uint16_t cmd_code = cmd->hdr.code;
	uint16_t ctrl_idx = cmd->hdr.ctrl_idx;

	if (status)
		*status = 0;

	err = mgmt_write_cmd(mgmt_fd, &packet);
	if (err)
		goto exit;

	while (!cmd_finished) {
		err = mgmt_read_evt(mgmt_fd, &packet);
		if (err)
			goto exit;

		if ((packet.hdr.code == MGMT_EVT_COMMAND_COMPLETE || packet.hdr.code == MGMT_EVT_COMMAND_STATUS) && packet.hdr.ctrl_idx == ctrl_idx) {
			struct __attribute__((__packed__)) parameters {
				uint16_t cmd_code;
				uint8_t status;
				uint8_t ret_param_data[];
			} *evt_params = (struct parameters *)packet.param_data;
			evt_params->cmd_code = btohs(evt_params->cmd_code);
			if (evt_params->cmd_code == cmd_code) {
				cmd_finished = true;
				if (status)
					*status = evt_params->status;
			}
		}
	}
	err = 0;
exit:
	return err;
}

static int read_mgmt_ver_info(int mgmt_fd, uint8_t *version, uint16_t *revision)
{
	int err;

	packet.hdr.code = 0x0001;
	packet.hdr.ctrl_idx = 0xFFFF;
	packet.hdr.param_len = 0;

	err = mgmt_send_cmd(mgmt_fd, &packet, NULL);
	if (err)
		goto exit;

	struct __attribute__((__packed__)) {
		uint16_t cmd_code;
		uint8_t status;
		uint8_t ver;
		uint16_t rev;
	} *evt_params = (void *)packet.param_data;

	*version = evt_params->ver;
	*revision = btohs(evt_params->rev);
	err = 0;
exit:
	return err;
}

static int read_ctrl_idx_list(int mgmt_fd, uint16_t *num_ctrls, uint16_t *ctrl_idxs, int max_ctrls)
{
	int err;

	packet.hdr.code = 0x0003;
	packet.hdr.ctrl_idx = 0xFFFF;
	packet.hdr.param_len = 0;

	err = mgmt_send_cmd(mgmt_fd, &packet, NULL);
	if (err)
		goto exit;

	struct __attribute__((__packed__)) {
		uint16_t cmd_code;
		uint8_t status;
		uint16_t num_ctrls;
		uint16_t ctrl_idxs[];
	} *evt_params = (void *)packet.param_data;

	*num_ctrls = btohs(evt_params->num_ctrls);

	for (int i = 0; i < *num_ctrls && i < max_ctrls; i++)
		ctrl_idxs[i] =  evt_params->ctrl_idxs[i];

	err = 0;
exit:
	return err;
}

static int read_ctrl_info(int mgmt_fd, uint16_t ctrl_idx, struct ctrl_info *info)
{
	int err;

	packet.hdr.code = 0x0004;
	packet.hdr.ctrl_idx = ctrl_idx;
	packet.hdr.param_len = 0;

	err = mgmt_send_cmd(mgmt_fd, &packet, NULL);
	if (err)
		goto exit;

	struct __attribute__((__packed__)) {
		uint16_t cmd_code;
		uint8_t status;
		uint8_t addr[6];
		uint8_t ver;
		uint16_t mfctr;
		uint32_t sup_set;
		uint32_t cur_set;
		uint8_t cod[3];
		uint8_t name[249];
		uint8_t short_name[11];
	} *evt_params = (void *)packet.param_data;

	memcpy(&info->address, evt_params->addr, sizeof(info->address));
	info->bluetooth_version = evt_params->ver;
	info->manufacturer = btohs(evt_params->mfctr);
	info->supported_settings = btohl(evt_params->sup_set);
	info->current_settings = btohl(evt_params->cur_set);
	info->class_of_device = (evt_params->cod[2] << 16) + (evt_params->cod[1] << 8) + evt_params->cod[0];

	memcpy(info->name, evt_params->name, sizeof(info->name));
	memcpy(info->short_name, evt_params->short_name, sizeof(info->short_name));

	err = 0;
exit:
	return err;
}

static int print_sco_routing(int dd)
{
	int err;
	struct hci_request request;

	static const char * const routes[] = {"PCM", "Transport", "CODEC", "I2S"};

	struct __attribute__((__packed__)) {
		uint8_t status;
		uint8_t sco_routing;
		uint8_t pcm_interface_rate;
		uint8_t frame_type;
		uint8_t sync_mode;
		uint8_t clock_mode;
	} ret_params;

	request.ogf = OGF_VENDOR_CMD;
	request.ocf = OCF_READ_SCO_PCM_INT_PARAM;
	request.cparam = NULL;
	request.clen = 0;
	request.rparam = &ret_params;
	request.rlen = sizeof(ret_params);
	request.event = EVT_CMD_COMPLETE;

	err = hci_send_req(dd, &request, 0);
	if (err || ret_params.status != 0) {
		printf("ERROR: Read_SCO_PCM_Int_Param failed; %s\n", strerror(errno));
		goto error;
	}

	printf("\t\tSCO_Routing: 0x%02X (%s)\n", ret_params.sco_routing, routes[ret_params.sco_routing]);

	err = 0;
error:
	return err;
}

static int print_cypress_info(int ctrl_idx)
{
	int err;
	int dd;
	struct hci_version ver;

	dd = hci_open_dev(ctrl_idx);
	if (dd < 0) {
		printf("ERROR: Unable to open device hci%d; %s\n", ctrl_idx, strerror(errno));
		err = dd;
		goto exit;
	}

	err = hci_read_local_version(dd, &ver, 0);
	if (err)
		goto close_dd;

	printf("\t\tRev: %03d.%03d.%03d.%04d\n", btohs(ver.lmp_subver) >> 13, (btohs(ver.lmp_subver) >> 8) & 0x1F,
			btohs(ver.lmp_subver) & 0xFF, btohs(ver.hci_rev) & 0x0FFF);

	err = print_sco_routing(dd);
	if (err)
		goto close_dd;

	err = 0;
close_dd:
	hci_close_dev(dd);
exit:
	return err;
}

int main(void)
{
	int err;
	uint8_t mgmt_ver;
	uint16_t mgmt_rev;
	uint16_t mgmt_num_ctrls;
	uint16_t mgmt_ctrl_idxs[8];
	int mgmt_fd;
	struct sockaddr_hci addr;

	mgmt_fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, BTPROTO_HCI);
	if (mgmt_fd < 0) {
		printf("ERROR: Unable to create Bluetooth management socket; %s\n", strerror(errno));
		err = mgmt_fd;
		goto exit;
	}

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	addr.hci_channel = HCI_CHANNEL_CONTROL;

	err = bind(mgmt_fd, (struct sockaddr *) &addr, sizeof(addr));
	if (err) {
		printf("ERROR: Unable to bind Bluetooth management socket; %s\n", strerror(errno));
		goto close_fd;
	}

	read_mgmt_ver_info(mgmt_fd, &mgmt_ver, &mgmt_rev);
	printf("Bluetooth Management version: %d.%d\n", mgmt_ver, mgmt_rev);

	read_ctrl_idx_list(mgmt_fd, &mgmt_num_ctrls, mgmt_ctrl_idxs, 8);
	printf("Number of controllers: %d\n", mgmt_num_ctrls);
	for (int i = 0; i < mgmt_num_ctrls && i < 8; i++) {
		struct ctrl_info info;
		char a[18];

		printf("\n\thci%d\n", mgmt_ctrl_idxs[i]);
		read_ctrl_info(mgmt_fd, mgmt_ctrl_idxs[i], &info);
		ba2str(&info.address, a);
		printf("\t\tName: %s\n", info.name);
		printf("\t\tAddress: %s\n", a);
		printf("\t\tManufacturer: %u\n", info.manufacturer);
		if (info.manufacturer == 305)	/* Cypress */
			print_cypress_info(mgmt_ctrl_idxs[i]);
	}

	err = 0;
close_fd:
	close(mgmt_fd);
exit:
	return err;
}
