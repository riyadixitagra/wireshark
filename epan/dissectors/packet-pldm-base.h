#include "config.h"
#include <epan/packet.h>

#include <stdint.h>
#ifndef PACKET_PLDM_H
#define PACKET_PLDM_H

static int pldmTA[5]={0};
static int pldmTI[32][5]={0};

static int proto_pldm=-1;
static int ett_pldm=-1;
static int proto_pldm_base=-1;

static int hf_source = -1;
static int hf_destination = -1;
static int hf_direction = -1;
static int hf_reserve = -1;
static int hf_instanceId = -1;
static int hf_headerVersion= -1;
static int hf_pldmSpec= -1;
static int hf_pldmCmdType=-1;
static int hf_resCompletion=-1;
static int hf_TIDValue=-1;
static int hf_DataTransferHandle=-1;
static int hf_TransferOperationFlag=-1;
static int hf_NextDataTransferHandle=-1;
static int hf_TransferFlag=-1;
static int hf_pldmVersion=-1;
static int hf_pldm_types=-1;
static int hf_pldmSpec8=-1;
static int hf_pldmBIOScmd=-1;
static int hf_pldmFruCmds=-1;
static int hf_pldmPlatformCmds=-1;
static int hf_pldmOEMCmds=-1;

typedef union {
        uint8_t byte;
        struct {
                uint8_t bit0 : 1;
                uint8_t bit1 : 1;
                uint8_t bit2 : 1;
                uint8_t bit3 : 1;
                uint8_t bit4 : 1;
                uint8_t bit5 : 1;
                uint8_t bit6 : 1;
                uint8_t bit7 : 1;
        } __attribute__((packed)) bits;
  } bitfield8_t;


static const value_string pldmBaseCmd[] = {
    { 1, "Set TID" },
    { 2, "Get TID" },
    { 3, "Get PLDM Version" },
    { 4, "Get PLDM Types" },
    { 5, "GetPLDMCommands" },
    { 0, NULL }
};

static const value_string specNames[] = {
    { 0, "PLDM Messaging and Discovery" },
    { 1 ,"PLDM for SMBIOS"},
    { 2, "PLDM Platform Monitoring and Control" },
    { 3, "PLDM for BIOS Control and Configuration" },
    { 4, "PLDM for FRU Data" },
    { 5, "PLDM for Firmware Update"},
    { 6, "PLDM for Redfish Device Enablement"},
    { 63,"OEM Specific"}
};
static const val64_string p_types[] = {
        {0, "base"},
        {1, "smbios"},
        {2, "platform"},
        {3, "bios"},
        {4, "fru"},
        {5, "fw_update"},
        {6, "rde"},
        {63,"oem"}
};


static const value_string pldmPlatformCmds[]={
    {4, "SetEventReceiver"},
    {10,"PlatformEventMessage"},
    {17,"GetSensorReading"},
    {33,"GetStateSensorReadings"},
    {49, "SetNumericEffecterValue"},
    {50,"GetNumericEffecterValue"},
    {57, "SetStateEffecterStates"},
    {81, "GetPDR"},
    {0, NULL} 
    };

static const value_string pldmFruCmds[]={
    {1, "GetFRURecordTableMetadata"},
    {2, "GetFRURecordTable"},
    {4, "GetFRURecordByOption"},
    {0, NULL}
    };

static const value_string pldmBIOScmd[]={
    {1, "GetBIOSTable"},
    {2, "SetBIOSTable"},
    {7, "SetBIOSAttributeCurrentValue"},
    {8, "GetBIOSAttributeCurrentValueByHandle"},
    {12,"GetDateTime"},
    {13,"SetDateTime"},
    { 0, NULL }
};

static const value_string pldmOEMCmds[]={
    {1,"GetFileTable"},
    {4,"ReadFile"},
    {5,"WriteFile"},
    {6,"ReadFileInToMemory"},
    {7,"WriteFileFromMemory"},
    {8,"ReadFileByTypeIntoMemory"},
    {9,"WriteFileByTypeFromMemory"},
    {10,"NewFileAvailable"},
    {11,"ReadFileByType"},
    {12,"WriteFileByType"},
    {13,"FileAck"}};


static const value_string transferOperationFlags[]={
    {0,"GetNextPart"},
    {1,"GetFirstPart"}
};

typedef struct pldm_version {
	guint8 major;
	guint8 minor;
	guint8 update;
	guint8 alpha;
} __attribute__((packed)) ver32_t;

static const value_string transferFlags[]={
    {1, "Start"},
    {2, "Middle"},
    {4, "End"},
    {5, "StartAndEnd"}
};

static int print_version_field(guint8 bcd, char *buffer, size_t buffer_size);
void ver2str(const ver32_t *version, char *buffer, size_t buffer_size);
void base_spec_cmds(guint8 pldmCmd, tvbuff_t *tvb, proto_tree *foo_tree, gint offset,  guint direction, guint8 instID);
void proto_register_base(void);
int 
dissect_base(tvbuff_t *tvb, packet_info *pinfo, proto_tree *p_tree, gint offset, guint8 pldmCmd, guint direction, guint8 instID, void* data _U_);
static int
dissect_pldm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
void
proto_register_foo(void);

#endif
