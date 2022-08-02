#include "config.h"
#include <epan/packet.h>
#include <stdint.h>
#include "packet-pldm-base.h"


static int ett1=-1;

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
	rc = g_snprintf(buffer, buffer_size, ".");
    }else{
       
        rc = g_snprintf(buffer, buffer_size, "-");
        POINTER_MOVE(rc, buffer, buffer_size, original_size);//reach minor
    }
    if(version-> minor != 0xff){
	POINTER_MOVE(rc, buffer, buffer_size, original_size);
	rc = print_version_field(version->minor, buffer, buffer_size);
	POINTER_MOVE(rc, buffer, buffer_size, original_size);
    }else{
        
        rc = g_snprintf(buffer, buffer_size, "-");
        POINTER_MOVE(rc, buffer, buffer_size, original_size);//reach update
    }
	if (version->update != 0xff) {
		rc = g_snprintf(buffer, buffer_size, ".");
		POINTER_MOVE(rc, buffer, buffer_size, original_size);
		rc = print_version_field(version->update, buffer, buffer_size);
		POINTER_MOVE(rc, buffer, buffer_size, original_size);
	}else{
        rc = g_snprintf(buffer, buffer_size, "-");
        POINTER_MOVE(rc, buffer, buffer_size, original_size);//reach alpha

    }
	if (version->alpha != 0xff) {
		rc = g_snprintf(buffer, buffer_size, "%c", version->alpha);
		POINTER_MOVE(rc, buffer, buffer_size, original_size);
	}
    else{
        rc = g_snprintf(buffer, buffer_size, "-");
    }
	// return original_size - buffer_size;
}

int 
dissect_base(tvbuff_t *tvb, packet_info *pinfo, proto_tree *p_tree, gint offset, guint8 pldmCmd, guint direction, guint8 instID, void* data _U_){

   switch(pldmCmd){
                    case 02: //GetTID
                            if(direction==0){//response
                                offset+=1;
                                proto_tree_add_item(p_tree, hf_TIDValue, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                            }
                            break;
                    case 03: //GetPLDMVersion
                            if(direction==1){//request
                                offset+=1;
                                proto_tree_add_item(p_tree, hf_DataTransferHandle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                offset+=1;
                                proto_tree_add_item(p_tree, hf_TransferOperationFlag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                                offset+=1;
                                proto_tree_add_item(p_tree, hf_pldmSpec8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                            }
                            else if(direction==0){
                                offset+=1;
                                proto_tree_add_item(p_tree, hf_NextDataTransferHandle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                offset+=4;
                                proto_tree_add_item(p_tree, hf_TransferFlag, tvb, offset, 1, ENC_LITTLE_ENDIAN);

                                offset+=1;
                                char buffer[16] = {0};
                                const ver32_t* buf;
                                buf = (ver32_t*)tvb_get_ptr(tvb, offset, 4);//check;
                                ver2str(buf, buffer, sizeof(buffer));
                                proto_tree_add_string(p_tree, hf_pldmVersion, tvb, offset, 4, buffer);
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
                                        proto_tree_add_uint64(p_tree, hf_pldm_types , tvb, offset, 64, i);
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
                                proto_tree_add_item(p_tree, hf_pldmSpec8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                                offset+=1;
                                char buffer[16] = {0};
                                const ver32_t* buf = (ver32_t*)tvb_get_ptr(tvb, offset, 4);
                                ver2str(buf, buffer, sizeof(buffer));
                                proto_tree_add_string(p_tree, hf_pldmVersion, tvb, offset, 4, buffer);
                            }
                            else if(direction==0 ){
                                if(pldmTI[instID][3]==1){
                                    offset+=1;
                                // g_print("pldm type at 332: %d\t%d\n",pldmT, pldmTA[pldmT]);
                                // g_print("zero : %d\t three : %d\n" , pldmTA[0], pldmTA[3]);
                                // if(pldmTA[pldmT]) g_print("success\n");
                                // if(pldmTA[4])g_print("fail\n");
                                guint16 byte=tvb_get_letohs(tvb, offset);
                                guint16 flag_bit=1;
                                for(guint8 i=0; i<16; i++, flag_bit<<=1){
                                    if(i>7 && i%8==0) offset+=1;
                                    if(byte & flag_bit){
                                        // g_print("%d\n", i);
                                        
                                        proto_tree_add_uint(p_tree, hf_pldmBIOScmd, tvb, offset, 1, i);
                                    }
                                    
                                }
                                }
                                if(pldmTI[instID][0]==1){
                                    offset+=1;
                                    guint8 byte=tvb_get_guint8(tvb, offset);
                                    guint8 flag_bit=1;
                                    for(guint8 i=0; i<8; i++, flag_bit<<=1){
                                        if(byte & flag_bit){
                                            proto_tree_add_uint(p_tree, hf_pldmCmdType, tvb, offset, 1, i);
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
                                            proto_tree_add_uint(p_tree, hf_pldmFruCmds, tvb, offset, 1, i);
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
                                            proto_tree_add_uint(p_tree, hf_pldmPlatformCmds, tvb, offset, 1, i);
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
                                            proto_tree_add_uint(p_tree, hf_pldmOEMCmds, tvb, offset, 1, i);
                                        }
                                        // if(i==12){
                                        //     i=191;
                                        // }
                                        
                                    }
                                    
                                }
                                
                            }
                            break;

                }

return tvb_captured_length(tvb);
}


void
proto_register_base(void)
{
    static hf_register_info hf[] ={
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
        }},
        { &hf_pldmCmdType,{
         	"PLDM Command Type", "pldm.baseCmd",
         	FT_UINT8, BASE_HEX,
         	VALS(pldmBaseCmd), 0x0,
         	NULL, HFILL}
         },
    };
    
   
    
    proto_pldm_base = proto_register_protocol (
        "PLDM base Protocol", /* name        */
        "PLDM_B",          /* short_name  */
        "pldm_b"           /* filter_name */
        );
    g_print("here at 505\n");
    proto_register_field_array(proto_pldm_base, hf, array_length(hf));
    register_dissector("pldm_b",dissect_base, proto_pldm_base);
    
}

void
proto_reg_handoff_base(void)
{
    static dissector_handle_t base_handle;
   
    base_handle = create_dissector_handle(dissect_base, proto_pldm_base);
    dissector_add_uint("wtap_encap",WTAP_ENCAP_USER0, base_handle);
}
