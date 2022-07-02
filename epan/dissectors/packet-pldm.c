#include "config.h"
#include <epan/packet.h>

#define PLDM_MIN_LENGTH 6
#define PLDM_MAX_TYPES 64

static int proto_pldm = -1;
static gint ett_pldm = -1;

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
static int hf_death=-1;


enum pldm_supported_types {
        PLDM_BASE = 0x00,
        PLDM_PLATFORM = 0x02,
        PLDM_BIOS = 0x03,
        PLDM_FRU = 0x04,
        PLDM_FWUP = 0x05,
        PLDM_OEM = 0x3F,
};
// const std::map<const char*, pldm_supported_types> pldmTypes {
//     {"base", PLDM_BASE},   {"platform", PLDM_PLATFORM},
//     {"bios", PLDM_BIOS},   {"fru", PLDM_FRU},
// };
// typedef union {
//         uint8_t byte;
//         struct {
//                 uint8_t bit0 : 1;
//                 uint8_t bit1 : 1;
//                 uint8_t bit2 : 1;
//                 uint8_t bit3 : 1;
//                 uint8_t bit4 : 1;
//                 uint8_t bit5 : 1;
//                 uint8_t bit6 : 1;
//                 uint8_t bit7 : 1;
//         } __attribute__((packed)) bits;
//   } bitfield8_t;


static const value_string directions[]={
    {01, "request"},
    {00, "response"}
};

static const value_string pldmNames[] = {
    { 1, "" },
    { 2, "platform monitoring and cntrl" },
    { 3, "Data" },
    { 0, "Messaging Control and Discovery/Base" }
};

static const value_string pldmBaseCmd[] = {
    { 1, "Set TID" },
    { 2, "Get TID" },
    { 3, "Get PLDM Version" },
    { 4, "Get PLDM Types" },
    { 5, "GetPLDMCommands" },
    { 0, NULL }
};

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

static const value_string transferFlags[]={
    {1, "Start"},
    {2, "Middle"},
    {4, "End"},
    {5, "StartAndEnd"}
};

guint* getpldmType(guint byte){
    static guint types[8];
    int j=0;
    for (int i = 0; i < PLDM_MAX_TYPES; i++){
        if(byte & (1<<(i%8))){
            // auto it = std::find_if(
            //     pldmTypes.begin(), pldmTypes.end(),
            //     [i](const auto& typePair) {
            //     return typePair.second == i; 
            //     }); 
            // if(it != pldmTypes.end()){
            //     types[j]=pldm_supported_types{it->second};
            // }
            if(arr[i]!=-1){
                type[j]=i;
                j++;
            }
        }
    }
    return types;
}

static int
dissect_pldm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PLDM");
    col_clear(pinfo->cinfo,COL_INFO);

    guint len= tvb_reported_length(tvb);

    if (len < PLDM_MIN_LENGTH) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Packet length %u, minimum %u",
                     len, PLDM_MIN_LENGTH);
        return tvb_captured_length(tvb);
    }
    else{
         proto_item *ti = proto_tree_add_item(tree, proto_pldm, tvb, 0, -1, ENC_NA);
    
        proto_tree *foo_tree = proto_item_add_subtree(ti, ett_pldm);
    
        gint offset = 0;
        guint direction = tvb_get_guint8(tvb, 2);
        
            proto_tree_add_item(foo_tree, hf_destination, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            // guint8 dest = tvb_get_guint8(tvb, offset);
            // col_clear(pinfo->destport,COL_DESTINATION);
            // col_add_fstr(pinfo->destport, COL_DESTINATION, "d ", dest);
            offset+=1;
            proto_tree_add_item(foo_tree, hf_source, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
       

        proto_tree_add_item(foo_tree, hf_direction, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        proto_tree_add_item(foo_tree, hf_reserve, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(foo_tree, hf_instanceId, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    
        offset+=1;
        guint8 ver4 = tvb_get_guint8(tvb, offset);
        guint8 specs= ver4 & 0x3F;
        proto_tree_add_item(foo_tree, hf_headerVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(foo_tree, hf_pldmSpec, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    
        offset+=1;
        guint8 pldmCmd = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(foo_tree, hf_pldmCmdType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        
        
        int reported_length = tvb_reported_length_remaining(tvb, 6);
	    if (reported_length >= 1) {
        	// guint resp = tvb_get_guint8(tvb, 6);
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
                                proto_tree_add_item(foo_tree, hf_pldmSpec, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                            }
                            else if(direction==0){
                                offset+=1;
                                proto_tree_add_item(foo_tree, hf_NextDataTransferHandle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                offset+=4;
                                proto_tree_add_item(foo_tree, hf_TransferFlag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                                offset+=1;
                               

                            }
                            break;
                    // case 04: //GetPLDMType
                    //         if(){
                    //              guint b1 = tvb_get_guint8(tvb, offset);
                    //             guint* types;
                    //             types=getpldmType(b1);
                    //         }
                
                }
            
    	    }
    		
    	
	    }
    }
    // if(tree){
    	 
    // }
    
    // offset+=1;

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
         	VALS(pldmNames), 0x3F,
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
        { &hf_death,{
         	"PLDM Type Allowed", "pldm.pType",
         	FT_UINT8, BASE_DEC,
         	VALS(pldmNames), 0x0,
         	NULL, HFILL}
         },
    };
    
    static gint *ett[] = {
        &ett_pldm
    };
    
    proto_pldm = proto_register_protocol (
        "PLDM Protocol", /* name        */
        "PLDM",          /* short_name  */
        "pldm"           /* filter_name */
        );
        
    proto_register_field_array(proto_pldm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("pldm",dissect_pldm, proto_pldm);
}

void
proto_reg_handoff_foo(void)
{
    static dissector_handle_t foo_handle;

    foo_handle = create_dissector_handle(dissect_pldm, proto_pldm);
    dissector_add_uint("wtap_encap",WTAP_ENCAP_USER0, foo_handle);
}



