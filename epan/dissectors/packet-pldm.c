#include "config.h"
#include "packet-pldm-base.h"
#include <epan/packet.h>
#include <stdint.h>

#define PLDM_MIN_LENGTH 6
#define PLDM_MAX_TYPES 8

static const value_string directions[]={
    {01, "request"},
    {00, "response"}
};


static const value_string completionCodes[]={
	{0, "Success"},
    {1, "ERROR"},
    {2, "ERROR_INVALID_DATA"},
    {3, "ERROR_INVALID_LENGTH"}
};

static int
dissect_pldm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PLDM");
    col_clear(pinfo->cinfo,COL_INFO);

    guint len, direction;
    gint offset;
    guint8 dest, instID, ver4, specs, pldmCmd;
    int reported_length;
    len=tvb_reported_length(tvb);
    // g_print("line 231 : %d\t%d\n", ett_pldm, ++out);
    direction = tvb_get_guint8(tvb, 2);
    if (len < PLDM_MIN_LENGTH) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Packet length %u, minimum %u",
                     len, PLDM_MIN_LENGTH);
        return tvb_captured_length(tvb);
    }
   if(direction>1){
        col_add_fstr( pinfo->cinfo, COL_INFO, "Packet invalid" );
        return tvb_captured_length(tvb);
    }
    else if (tree){
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
                // base_spec_cmds(pldmCmd, tvb, foo_tree, offset, direction, instID);
                dissect_base(tvb, pinfo, foo_tree, offset, pldmCmd, direction, instID, data);
                // g_print("line 231 : %d\n", t);
                
            }
            
    	}
    		
    	
	}
    
    return tvb_captured_length(tvb);
}

void
proto_register_pldm(void)
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
    static dissector_handle_t foo_handle, base_handle;
    g_print("here at 512\n");
    base_handle = create_dissector_handle(dissect_base, proto_pldm_base);
    
    dissector_add_uint("wtap_encap",WTAP_ENCAP_USER1, base_handle);
    foo_handle = create_dissector_handle(dissect_pldm, proto_pldm);
    dissector_add_uint("wtap_encap",WTAP_ENCAP_USER0, foo_handle);
     
}





