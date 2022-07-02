#include "config.h"
#include <epan/packet.h>
#include <stdint.h>

#define PLDM_MIN_LENGTH 6
#define PLDM_MAX_TYPES 8


static int proto_pldm = -1;
static gint ett_pldm = -1;
static int out=0, in=100;

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


static const value_string directions[]={
    {01, "request"},
    {00, "response"}
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



static const value_string pldmBaseCmd[] = {
    { 1, "Set TID" },
    { 2, "Get TID" },
    { 3, "Get PLDM Version" },
    { 4, "Get PLDM Types" },
    { 5, "GetPLDMCommands" },
    { 0, NULL }
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

static const value_string completionCodes[]={
	{0, "Success"},
    {1, "ERROR"},
    {2, "ERROR_INVALID_DATA"},
    {3, "ERROR_INVALID_LENGTH"}
};

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


static int print_version_field(guint8 bcd, char *buffer, size_t buffer_size)
{
	int v;
	if (bcd == 0xff)
		return 0;
	if ((bcd & 0xf0) == 0xf0) {
		v = bcd & 0x0f;
		return g_snprintf(buffer, buffer_size, "%d", v);
	}
	v = ((bcd >> 4) * 10) + (bcd & 0x0f);
	return g_snprintf(buffer, buffer_size, "%02d", v);
}

#define POINTER_MOVE(rc, buffer, buffer_size, original_size)    \               
	do {                                                        \           
		if (rc < 0)                                               \     
			return rc;                                             \
		if ((size_t)rc >= buffer_size)                              \   
			return original_size - 1;                              \
		buffer += rc;                                               \   
		buffer_size -= rc;                                           \  
	} while (0);\

void ver2str(const ver32_t *version, char *buffer, size_t buffer_size)
{
	int rc;
	size_t original_size;
    original_size = buffer_size;
    if(version-> major != 0xff){
	rc = print_version_field(version->major, buffer, buffer_size);
	POINTER_MOVE(rc, buffer, buffer_size, original_size);
	rc = g_snprintf(buffer, buffer_size, ".");}
	POINTER_MOVE(rc, buffer, buffer_size, original_size);
	rc = print_version_field(version->minor, buffer, buffer_size);
	POINTER_MOVE(rc, buffer, buffer_size, original_size);
	if (version->update != 0xff) {
		rc = g_snprintf(buffer, buffer_size, ".");
		POINTER_MOVE(rc, buffer, buffer_size, original_size);
		rc = print_version_field(version->update, buffer, buffer_size);
		POINTER_MOVE(rc, buffer, buffer_size, original_size);
	}
	if (version->alpha != 0) {
		rc = g_snprintf(buffer, buffer_size, "%c", version->alpha);
		POINTER_MOVE(rc, buffer, buffer_size, original_size);
	}
	// return original_size - buffer_size;
}


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
guint pldmTA[5]={0};
guint pldmTI[32][5]={0};


static int
dissect_pldm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PLDM");
    col_clear(pinfo->cinfo,COL_INFO);

    guint len, direction;
    gint offset;
    guint8 dest, instID, ver4, specs, pldmCmd;
    int reported_length;
    len=tvb_reported_length(tvb);
    // g_print("line 231 : %d\t%d\n", ett_pldm, ++out);

    if (len < PLDM_MIN_LENGTH) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Packet length %u, minimum %u",
                     len, PLDM_MIN_LENGTH);
        return tvb_captured_length(tvb);
    }else if (tree){
        proto_item *ti = proto_tree_add_item(tree, proto_pldm, tvb, 0, -1, ENC_NA);
        proto_tree *foo_tree = proto_item_add_subtree(ti, ett_pldm);
        offset= 0;
        direction = tvb_get_guint8(tvb, 2);
        proto_tree_add_item(foo_tree, hf_destination, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        dest = tvb_get_guint8(tvb, offset);
        offset+=1;
        proto_tree_add_item(foo_tree, hf_source, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        proto_tree_add_item(foo_tree, hf_direction, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        proto_tree_add_item(foo_tree, hf_reserve, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(foo_tree, hf_instanceId, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        instID= tvb_get_guint8(tvb, offset);
        instID=instID & 0x1F;
        offset+=1;
        ver4= tvb_get_guint8(tvb, offset);
        specs= ver4 & 0x3F;
        proto_tree_add_item(foo_tree, hf_headerVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(foo_tree, hf_pldmSpec, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        pldmCmd = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(foo_tree, hf_pldmCmdType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        reported_length = tvb_reported_length_remaining(tvb, 6);

	if (reported_length >= 1) {
        	if (direction== 0) {//completion byte in response
            		offset+=1;
        		    proto_tree_add_item(foo_tree, hf_resCompletion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    		}
            if(specs==0){//base spec
                switch(pldmCmd){
                    case 02: //GetTID
                            if(direction==0){//response
                                offset+=1;
                                proto_tree_add_item(foo_tree, hf_TIDValue, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                            }
                            break;
                    case 03: //GetPLDMVersion
                            if(direction==1){//request
                                offset+=1;
                                proto_tree_add_item(foo_tree, hf_DataTransferHandle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                offset+=1;
                                proto_tree_add_item(foo_tree, hf_TransferOperationFlag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                                offset+=1;
                                proto_tree_add_item(foo_tree, hf_pldmSpec8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                            }
                            else if(direction==0){
                                offset+=1;
                                proto_tree_add_item(foo_tree, hf_NextDataTransferHandle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                offset+=4;
                                proto_tree_add_item(foo_tree, hf_TransferFlag, tvb, offset, 1, ENC_LITTLE_ENDIAN);

                                offset+=1;
                                char buffer[16] = {0};
                                const ver32_t* buf;
                                buf = (ver32_t*)tvb_get_ptr(tvb, offset, 4);
                                ver2str(buf, buffer, sizeof(buffer));
                                proto_tree_add_string(foo_tree, hf_pldmVersion, tvb, offset, 4, buffer);
                            }
                            break;
                    case 04: //GetPLDMTypes
                            if(direction==0){
                                offset+=1;
                                guint64 types = tvb_get_letoh64(tvb,offset);
                                guint64 flag_bit, i;
                                flag_bit= 1;
                                for( i = 0 ; i < 64; i++, flag_bit<<=1 )
                                {
	                                if(types & flag_bit)
	                                {
                                        if(i>7 && i/8==0) offset+=1;
                                        proto_tree_add_uint64(foo_tree, hf_pldm_types , tvb, offset, 64, i);
	                                }
                                }
                            }
                            break;
                    case 05: //GetPLDMCommands
                            static uint8_t pldmT;
                            if(direction==1){
                                offset+=1;
                                pldmT=tvb_get_guint8(tvb, offset);//error! reponse depends on this
                                pldmTA[pldmT]=1;
                                pldmTI[instID][pldmT]=1;
                                // g_print("pldm type at 332: %d\n", pldmT);
                                proto_tree_add_item(foo_tree, hf_pldmSpec8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                                offset+=1;
                                char buffer[16] = {0};
                                const ver32_t* buf = (ver32_t*)tvb_get_ptr(tvb, offset, 4);
                                ver2str(buf, buffer, sizeof(buffer));
                                proto_tree_add_string(foo_tree, hf_pldmVersion, tvb, offset, 4, buffer);
                            }
                            else if(direction==0 ){
                                if(pldmTI[instID][3]==1){
                                    offset+=1;
                                guint16 byte=tvb_get_letohs(tvb, offset);
                                guint16 flag_bit=1;
                                for(guint8 i=0; i<16; i++, flag_bit<<=1){
                                    if(i>7 && i%8==0) offset+=1;
                                    if(byte & flag_bit){
                                        proto_tree_add_uint(foo_tree, hf_pldmBIOScmd, tvb, offset, 1, i);
                                    }
                                    
                                }
                                }
                                if(pldmTI[instID][0]==1){
                                    offset+=1;
                                    guint8 byte=tvb_get_guint8(tvb, offset);
                                    guint8 flag_bit=1;
                                    for(guint8 i=0; i<8; i++, flag_bit<<=1){
                                        if(byte & flag_bit){
                                            proto_tree_add_uint(foo_tree, hf_pldmCmdType, tvb, offset, 1, i);
                                        }
                                    }
                                }
                                if(pldmTI[instID][4]==1){
                                    offset+=1;
                                    guint64 byte=tvb_get_letoh64(tvb, offset);
                                    guint64 flag_bit=1;
                                    for(guint8 i=0; i<64; i++, flag_bit<<=1){
                                        if(i>7 && i%8==0) offset+=1;
                                        if(byte & flag_bit){
                                            proto_tree_add_uint(foo_tree, hf_pldmFruCmds, tvb, offset, 1, i);
                                        }
                                    }
                                }
                                if(pldmTI[instID][2]==1){
                                    offset+=1;
                                    guint64 b1=tvb_get_letoh64(tvb, offset);
                                    guint64 b2=tvb_get_letoh64(tvb, offset+8);
                                    guint64 b3=tvb_get_letoh64(tvb, offset+16);
                                    guint64 b4=tvb_get_letoh64(tvb, offset+24);
                                    guint64 byt[4];
                                    byt[0]=b1;
                                    byt[1]=b2;
                                    byt[2]=b3;
                                    byt[3]=b4;
                                    guint64 flag_bit=1;
                                    for(guint8 i=0; i<88; i++, flag_bit<<=1){
                                        if(i==64){
                                            flag_bit=1;
                                        }
                                        int j=i/64;
                                        if(i>7 && i%8==0) offset+=1;
                                        guint64 byte= byt[j];
                                        if(byte & flag_bit){
                                            proto_tree_add_uint(foo_tree, hf_pldmPlatformCmds, tvb, offset, 1, i);
                                        }
                                        
                                    }
                                }
                                if(pldmTI[instID][63]==1){
                                    offset+=1;
                                    guint64 b1=tvb_get_letoh64(tvb, offset);
                                    guint64 b2=tvb_get_letoh64(tvb, offset+8);
                                    guint64 b3=tvb_get_letoh64(tvb, offset+16);
                                    guint64 b4=tvb_get_letoh64(tvb, offset+24);
                                    guint64 byt[4];
                                    byt[0]=b1;
                                    byt[1]=b2;
                                    byt[2]=b3;
                                    byt[3]=b4;
                                    guint64 flag_bit=1;
                                    for(guint8 i=0; i<16; i++, flag_bit<<=1){
                                        if(i==64||i==128||i==192){
                                            flag_bit=1;
                                        }
                                        int j=i/64;
                                        if(i>7 && i%8==0){
                                            offset+=1;
                                        } 
                                        guint64 byte= byt[j];
                                        if(byte & flag_bit){
                                            proto_tree_add_uint(foo_tree, hf_pldmOEMCmds, tvb, offset, 1, i);
                                        }
                                        
                                    }
                                    
                                }
                                
                                
                            }
                            break;

                }
                
            }
            
    	}
    		
    	
	}
    

    return tvb_captured_length(tvb);
}

void
proto_register_foo(void)
{
     static hf_register_info hf[] = {
         { &hf_source,
            { "Msg Source", "pldm.source",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_destination,
            { "Msg Destination", "pldm.dest",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_direction,
            { "Msg Direction", "pldm.direction",
            FT_UINT8, BASE_DEC,
            VALS(directions), 0x0,
            NULL, HFILL }
        },
        { &hf_reserve,
            { "PLDM Reserve", "pldm.r",
            FT_UINT8, BASE_DEC,
            NULL, 0xE0,
            NULL, HFILL }
        },
        { &hf_instanceId,
        	{ "PLDM Instance Id", "pldm.instance",
        	  FT_UINT8, BASE_DEC,
        	  NULL, 0x1F,
        	  NULL, HFILL}
         },
        { &hf_headerVersion,{
        	"PLDM Header Version", "pldm.hdr",
        	FT_UINT8, BASE_DEC,
        	NULL, 0xC0,
        	NULL, HFILL}
         },
         { &hf_pldmSpec,{
         	"PLDM Spec", "pldm.spec",
         	FT_UINT8, BASE_DEC,
         	VALS(specNames), 0x3F,
         	NULL, HFILL}
         },
         { &hf_pldmCmdType,{
         	"PLDM Command Type", "pldm.baseCmd",
         	FT_UINT8, BASE_HEX,
         	VALS(pldmBaseCmd), 0x0,
         	NULL, HFILL}
         },
         { &hf_resCompletion,{
         	"Completion Response", "pldm.res",
         	FT_UINT8, BASE_DEC,
         	VALS(completionCodes), 0x0,
         	NULL, HFILL}
         },
         { &hf_TIDValue,{
         	"TID", "pldm.TID",
         	FT_UINT8, BASE_DEC,
         	NULL, 0x0,
         	NULL, HFILL}
         },
         {&hf_DataTransferHandle,{
            "Data Transfer Handle", "pldm.transferHandle",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
         }},
         {&hf_TransferOperationFlag,{
            "Transfer Operation Flag", "pldm.operationFlag",
            FT_UINT8, BASE_DEC,
            VALS(transferOperationFlags), 0x0,
            NULL, HFILL}
         },
         {&hf_NextDataTransferHandle,{
             "NextDataTransferHandle", "pldm.nextDataTransferHandle",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
            NULL, HFILL
         }},   
        {&hf_TransferFlag,{
            "Transfer Flag", "pldm.transferFlag",
            FT_UINT8, BASE_DEC,
            VALS(transferFlags), 0x0,
            NULL, HFILL
        }},
        {&hf_pldmSpec8,{
            "PLDMType", "pldm.ty",
            FT_UINT8, BASE_DEC,
            VALS(specNames), 0x0,
            NULL, HFILL
        }},
        {&hf_pldmVersion,{
            "PLDM Version", "pldm.version",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
        }},
        {&hf_pldm_types,{
            "pldm type supported :", "pldm.type",
            FT_UINT64, BASE_DEC | BASE_VAL64_STRING ,
            VALS64(p_types),0x0,
            NULL,HFILL
        }},
        { &hf_pldmBIOScmd,{
            "pldm type supported :", "pldm.xyz",
            FT_UINT8, BASE_DEC,
            VALS(pldmBIOScmd), 0x0,
            NULL, HFILL
        }}, 
        { &hf_pldmFruCmds,{
            "pldm type supported : ", "pldm.fru",
            FT_UINT8, BASE_DEC,
            VALS(pldmFruCmds), 0x0,
            NULL, HFILL
        }},
        { &hf_pldmPlatformCmds, {
            "pldm type supported : ", "pldm.platform",
            FT_UINT8, BASE_DEC,
            VALS(pldmPlatformCmds), 0x0,
            NULL, HFILL
        }},
        {&hf_pldmOEMCmds, {
            "pldm type supported : ", "pldm.oem",
            FT_UINT8, BASE_DEC,
            VALS(pldmOEMCmds), 0x0,
            NULL, HFILL
        }}
    };
    
    static gint *ett[] = {
        &ett_pldm
    };
    
    proto_pldm = proto_register_protocol (
        "PLDM Protocol", /* name        */
        "PLDM",          /* short_name  */
        "pldm"           /* filter_name */
        );
    g_print("here at 502\n");
    proto_register_field_array(proto_pldm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("pldm",dissect_pldm, proto_pldm);
}

void
proto_reg_handoff_foo(void)
{
    static dissector_handle_t foo_handle;
    g_print("here at 512\n");
    foo_handle = create_dissector_handle(dissect_pldm, proto_pldm);
    dissector_add_uint("wtap_encap",WTAP_ENCAP_USER0, foo_handle);
}



