/* packet-zbee-tlv.c
 * Dissector routines for the Zbee TLV (R23+)
 * Copyright 2021 DSR Corporation, http://dsr-wireless.com/
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/proto_data.h>

#include "packet-ieee802154.h"
#include "packet-ieee802154.h"
#include "packet-zbee-tlv.h"
#include "packet-zbee.h"
#include "packet-zbee-nwk.h"
#include "packet-zbee-zdp.h"
#include "packet-zbee-aps.h"

#include "conversation.h"

/*-------------------------------------
 * Dissector Function Prototypes
 *-------------------------------------
 */
static int   dissect_zbee_tlv_default(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
static guint dissect_zdp_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, guint cmd_id);
static guint dissect_aps_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, void *data, guint cmd_id);
static guint dissect_unknown_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);

//Global TLV Dissector Routines
static guint dissect_zbee_tlv_manufacturer_specific(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, guint8 length);
static guint dissect_zbee_tlv_supported_key_negotiation_methods(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);
static guint dissect_zbee_tlv_configuration_parameters(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);
static guint dissect_zbee_tlv_dev_cap_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);
static guint dissect_zbee_tlv_panid_conflict_report(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);
static guint dissect_zbee_tlv_next_pan_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);
static guint dissect_zbee_tlv_next_channel_change(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);
static guint dissect_zbee_tlv_passphrase(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);
static guint dissect_zbee_tlv_router_information(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);
static guint dissect_zbee_tlv_fragmentation_parameters(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);
static guint dissect_zbee_tlv_potential_parents(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);

//Local TLV Dissector Routines
static guint dissect_zbee_tlv_selected_key_negotiation_method(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);
static guint dissect_zbee_tlv_curve25519_public_point(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);
static guint dissect_zbee_tlv_eui64(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);
static guint dissect_zbee_tlv_clear_all_bindigs_eui64(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);
static guint dissect_zbee_tlv_requested_auth_token_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);
static guint dissect_zbee_tlv_target_ieee_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);
static guint dissect_zbee_tlv_device_auth_level(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset);

void proto_register_zbee_tlv(void);

/* Initialize Protocol and Registered fields */
static int proto_zbee_tlv = -1;
static dissector_handle_t zigbee_aps_handle;

static int hf_zbee_tlv_global_type = -1;
static int hf_zbee_tlv_local_type_key_update_req_rsp = -1;
static int hf_zbee_tlv_local_type_key_negotiation_req_rsp = -1;
static int hf_zbee_tlv_local_type_get_auth_level_rsp = -1;
static int hf_zbee_tlv_local_type_clear_all_bindings_req = -1;
static int hf_zbee_tlv_local_type_req_security_get_auth_token = -1;
static int hf_zbee_tlv_local_type_req_security_get_auth_level = -1;
static int hf_zbee_tlv_local_type_req_security_decommission = -1;
static int hf_zbee_tlv_local_type_req_beacon_survey = -1;
static int hf_zbee_tlv_local_type_rsp_beacon_survey = -1;
static int hf_zbee_tlv_local_type_req_challenge = -1;
static int hf_zbee_tlv_local_type_rsp_challenge = -1;
static int hf_zbee_tlv_local_type_rsp_set_configuration = -1;

static int hf_zbee_tlv_length = -1;
static int hf_zbee_tlv_type = -1;
static int hf_zbee_tlv_value = -1;
static int hf_zbee_tlv_count = -1;
static int hf_zbee_tlv_manufacturer_specific = -1;

static int hf_zbee_zdp_tlv_status_count = -1;
static int hf_zbee_zdp_tlv_type_id = -1;
static int hf_zbee_zdp_tlv_proc_status = -1;

static int hf_zbee_tlv_next_pan_id = -1;
static int hf_zbee_tlv_next_channel_change =-1;
static int hf_zbee_tlv_passphrase = -1;
static int hf_zbee_tlv_configuration_param = -1;
static int hf_zbee_tlv_configuration_param_restricted_mode =-1;
static int hf_zbee_tlv_configuration_param_link_key_enc = -1;
static int hf_zbee_tlv_configuration_param_leave_req_allowed = -1;

static int hf_zbee_tlv_dev_cap_ext_capability_information = -1;
static int hf_zbee_tlv_dev_cap_ext_zbdirect_virt_device = -1;

static int hf_zbee_tlv_challenge_value = -1;
static int hf_zbee_tlv_aps_frame_counter = -1;
static int hf_zbee_tlv_challenge_counter = -1;
static int hf_zbee_tlv_mic64 = -1;

static int hf_zbee_tlv_lqa = -1;

static int hf_zbee_tlv_router_information = -1;
static int hf_zbee_tlv_router_information_hub_connectivity = -1;
static int hf_zbee_tlv_router_information_uptime = -1;
static int hf_zbee_tlv_router_information_pref_parent = -1;
static int hf_zbee_tlv_router_information_battery_backup = -1;
static int hf_zbee_tlv_router_information_enhanced_beacon_request_support = -1;
static int hf_zbee_tlv_router_information_mac_data_poll_keepalive_support = -1;
static int hf_zbee_tlv_router_information_end_device_keepalive_support = -1;
static int hf_zbee_tlv_router_information_power_negotiation_support = -1;

static int hf_zbee_tlv_node_id = -1;
static int hf_zbee_tlv_frag_opt = -1;
static int hf_zbee_tlv_max_reassembled_buf_size = -1;

static int hf_zbee_tlv_supported_key_negotiation_methods = -1;
static int hf_zbee_tlv_supported_key_negotiation_methods_key_request = -1;
static int hf_zbee_tlv_supported_key_negotiation_methods_ecdhe_using_curve25519_aes_mmo128 = -1;
static int hf_zbee_tlv_supported_key_negotiation_methods_ecdhe_using_curve25519_sha256 = -1;
static int hf_zbee_tlv_supported_secrets = -1;
static int hf_zbee_tlv_supported_preshared_secrets_auth_token = -1;
static int hf_zbee_tlv_supported_preshared_secrets_ic = -1;
static int hf_zbee_tlv_supported_preshared_secrets_passcode_pake = -1;
static int hf_zbee_tlv_supported_preshared_secrets_basic_access_key = -1;
static int hf_zbee_tlv_supported_preshared_secrets_admin_access_key = -1;

static int hf_zbee_tlv_panid_conflict_cnt = -1;

static int hf_zbee_tlv_selected_key_negotiation_method = -1;
static int hf_zbee_tlv_selected_pre_shared_secret = -1;
static int hf_zbee_tlv_device_eui64 = -1;
static int hf_zbee_tlv_curve25519_public_point = -1;
static int hf_zbee_tlv_global_tlv_id = -1;
static int hf_zbee_tlv_local_ieee_addr = -1;
static int hf_zbee_tlv_local_initial_join_method = -1;
static int hf_zbee_tlv_local_active_lk_type = -1;

static int hf_zbee_tlv_relay_msg_type = -1;
static int hf_zbee_tlv_relay_msg_length = -1;
static int hf_zbee_tlv_relay_msg_joiner_ieee = -1;

/* Subtree indices. */
static gint ett_zbee_aps_tlv = -1;
static gint ett_zbee_aps_relay = -1;
static gint ett_zbee_tlv = -1;
static gint ett_zbee_tlv_supported_key_negotiation_methods = -1;
static gint ett_zbee_tlv_supported_secrets = -1;
static gint ett_zbee_tlv_router_information = -1;
static gint ett_zbee_tlv_configuration_param = -1;
static gint ett_zbee_tlv_capability_information = -1;


static const value_string zbee_aps_relay_tlvs[] = {
    { 0,          "Relay Message TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_global_types[] = {
    { ZBEE_TLV_TYPE_MANUFACTURER_SPECIFIC,                "Manufacturer Specific Global TLV" },
    { ZBEE_TLV_TYPE_SUPPORTED_KEY_NEGOTIATION_METHODS,    "Supported Key Negotiation Methods Global TLV" },
    { ZBEE_TLV_TYPE_PANID_CONFLICT_REPORT,                "PAN ID Conflict Report Global TLV"},
    { ZBEE_TLV_TYPE_NEXT_PAN_ID,                          "Next PAN ID Global TLV" },
    { ZBEE_TLV_TYPE_NEXT_CHANNEL_CHANGE,                  "Next Channel Change Global TLV" },
    { ZBEE_TLV_TYPE_PASSPHRASE,                           "Passphrase Global TLV" },
    { ZBEE_TLV_TYPE_ROUTER_INFORMATION,                   "Router Information Global TLV" },
    { ZBEE_TLV_TYPE_FRAGMENTATION_PARAMETERS,             "Fragmentation Parameters Global TLV" },
    { ZBEE_TLV_TYPE_JOINER_ENCAPSULATION_GLOBAL,          "Joiner Encapsulation Global TLV" },
    { ZBEE_TLV_TYPE_BEACON_APPENDIX_ENCAPSULATION_GLOBAL, "Beacon Appendix Encapsulation Global TLV" },
    { ZBEE_TLV_TYPE_CONFIGURATION_MODE_PARAMETERS,        "Configuration Mode Parameters Global TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_key_update_req_rsp[] = {
    { ZBEE_TLV_TYPE_KEY_UPD_REQ_SELECTED_KEY_NEGOTIATION_METHOD,   "Selected Key Negotiations Method Local TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_key_negotiation_req_rsp[] = {
    { ZBEE_TLV_TYPE_KEY_NEG_REQ_CURVE25519_PUBLIC_POINT,           "Curve25519 Public Point Local TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_get_auth_level_rsp[] = {
    { ZBEE_TLV_TYPE_GET_AUTH_LEVEL,                    "Device Authentication Level TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_clear_all_bindings_req[] = {
    { ZBEE_TLV_TYPE_CLEAR_ALL_BINDIGS_REQ_EUI64,       "Clear All Bindings Req EUI64 TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_req_security_get_auth_token[] = {
    { ZBEE_TLV_TYPE_REQUESTED_AUTH_TOKEN_ID,           "Requested Authentication Token ID TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_req_security_get_auth_level[] = {
    { ZBEE_TLV_TYPE_TARGET_IEEE_ADDRESS,               "Target IEEE Address TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_req_security_decommission[] = {
    { ZBEE_TLV_TYPE_EUI64,                             "EUI64 TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_req_beacon_survey[] = {
    { ZBEE_TLV_TYPE_BEACON_SURVEY_CONFIGURATION,       "Beacon Survey Configuration TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_req_challenge[] = {
    { 0,       "APS Frame Counter Challenge Request TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_rsp_challenge[] = {
    { 0,       "APS Frame Counter Challenge Response TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_rsp_set_configuration[] = {
    { 0,       "Processing status TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_rsp_beacon_survey[] = {
    { ZBEE_TLV_TYPE_BEACON_SURVEY_CONFIGURATION,       "Beacon Survey Configuration TLV" },
    { ZBEE_TLV_TYPE_BEACON_SURVEY_RESULTS,             "Beacon Survey Results TLV" },
    { ZBEE_TLV_TYPE_BEACON_SURVEY_POTENTIAL_PARENTS,   "Beacon Survey Potential Parents TLV"},
    { 0, NULL }
};

static const value_string zbee_tlv_selected_key_negotiation_method[] = {
    { ZBEE_TLV_SELECTED_KEY_NEGOTIATION_METHODS_ZB_30,                             "Zigbee 3.0" },
    { ZBEE_TLV_SELECTED_KEY_NEGOTIATION_METHODS_ECDHE_USING_CURVE25519_AES_MMO128, "ECDHE using Curve25519 with Hash AES-MMO-128" },
    { ZBEE_TLV_SELECTED_KEY_NEGOTIATION_METHODS_ECDHE_USING_CURVE25519_SHA256,     "ECDHE using Curve25519 with Hash SHA-256" },
    { 0, NULL }
};

static const value_string zbee_tlv_selected_pre_shared_secret[] = {
    { ZBEE_TLV_SELECTED_PRE_SHARED_WELL_KNOWN_KEY,            "Well Known Key" },
    { ZBEE_TLV_SELECTED_PRE_SHARED_SECRET_AUTH_TOKEN,         "Symmetric Authentication Token" },
    { ZBEE_TLV_SELECTED_PRE_SHARED_SECRET_LINK_KEY_IC,        "Pre-configured link-ley derived from installation code" },
    { ZBEE_TLV_SELECTED_PRE_SHARED_SECRET_VLEN_PASSCODE,      "Variable-length pass code" },
    { ZBEE_TLV_SELECTED_PRE_SHARED_SECRET_BASIC_ACCESS_KEY,   "Basic Access Key" },
    { ZBEE_TLV_SELECTED_PRE_SHARED_SECRET_ADMIN_ACCESS_KEY,   "Administrative Access Key" },
    { 0, NULL }
};

static const value_string zbee_initial_join_methods[] = {
    { 0x00, "No authentication" },
    { 0x01, "Install Code Key" },
    { 0x02, "Anonymous key negotiation" },
    { 0x03, "Authentication Key Negotiation" },
    { 0, NULL }
};

static const value_string zbee_active_lk_types[] = {
    { 0x00, "Not Updated" },
    { 0x01, "Key Request Method" },
    { 0x02, "Unauthentication Key Negotiation" },
    { 0x03, "Authentication Key Negotiation" },
    { 0x04, "Application Defined Certificate Based Mutual" },
    { 0, NULL }
};

static guint
dissect_aps_relay_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, void *data)
{
  tvbuff_t    *relay_tvb;
  proto_item  *relayed_frame_root;
  proto_tree  *relayed_frame_tree;
  guint8      length;
  zbee_nwk_hints_t *nwk_hints;

  zigbee_aps_handle = find_dissector("zbee_aps");

  proto_tree_add_item(tree, hf_zbee_tlv_relay_msg_type, tvb, offset, 1, ENC_NA);
  offset += 1;

  length = tvb_get_guint8(tvb, offset) + 1;
  proto_tree_add_item(tree, hf_zbee_tlv_relay_msg_length, tvb, offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_zbee_tlv_relay_msg_joiner_ieee, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  nwk_hints = (zbee_nwk_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo,
                                                   proto_get_id_by_filter_name(ZBEE_PROTOABBREV_NWK), 0);
  nwk_hints->joiner_addr64 = tvb_get_letoh64(tvb, offset);
  offset += 8;

  /* The remainder is a relayed APS frame. */
  relay_tvb = tvb_new_subset_remaining(tvb, offset);
  relayed_frame_tree = proto_tree_add_subtree_format(tree, tvb, offset, length - 8, ett_zbee_aps_relay, &relayed_frame_root,
          "Relayed APS Frame");
  call_dissector_with_data(zigbee_aps_handle, relay_tvb, pinfo, relayed_frame_tree, data);

  /* Add column info */
  col_append_str(pinfo->cinfo, COL_INFO, ", Relay");

  return tvb_captured_length(tvb);
}


static guint
dissect_aps_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, void *data, guint cmd_id)
{
    switch (cmd_id) {
        case ZBEE_APS_CMD_RELAY_MSG_UPSTREAM:
        case ZBEE_APS_CMD_RELAY_MSG_DOWNSTREAM:
        {
            zbee_nwk_hints_t *nwk_hints  = (zbee_nwk_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo,
                      proto_get_id_by_filter_name(ZBEE_PROTOABBREV_NWK), 0);
            nwk_hints->relay_type = (cmd_id == ZBEE_APS_CMD_RELAY_MSG_DOWNSTREAM ? ZBEE_APS_RELAY_DOWNSTREAM : ZBEE_APS_RELAY_UPSTREAM);
        }
            offset = dissect_aps_relay_local_tlv(tvb, pinfo, tree, offset, data);
            break;

        default:
        {
            offset = dissect_unknown_tlv(tvb, pinfo, tree, offset);
            break;
        }
    }

    return offset;
}

/*
 *Helper dissector for the Security Decommission Request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static guint
dissect_zdp_req_security_decommission_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  type;
    guint8  length;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_req_security_decommission, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
        case ZBEE_TLV_TYPE_EUI64:
            offset = dissect_zbee_tlv_eui64(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the Security Get Authentication Level Request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static guint
dissect_zdp_req_security_get_auth_level_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  type;
    guint8  length;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_req_security_get_auth_level, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
        case ZBEE_TLV_TYPE_TARGET_IEEE_ADDRESS:
            offset = dissect_zbee_tlv_target_ieee_address(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}
/*
 *Helper dissector for the Security Get Authentication Token Request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static guint
dissect_zdp_req_security_get_auth_token_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  type;
    guint8  length;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_req_security_get_auth_token, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
        case ZBEE_TLV_TYPE_REQUESTED_AUTH_TOKEN_ID:
            offset = dissect_zbee_tlv_requested_auth_token_id(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the Clear All Bindings Request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static guint
dissect_zdp_req_clear_all_bindings_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  type;
    guint8  length;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_clear_all_bindings_req, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
        case ZBEE_TLV_TYPE_CLEAR_ALL_BINDIGS_REQ_EUI64:
            offset = dissect_zbee_tlv_clear_all_bindigs_eui64(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the Beacon Survey Request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static guint
dissect_zdp_req_beacon_survey_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  type;
    guint8  length;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_req_beacon_survey, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
        case ZBEE_TLV_TYPE_BEACON_SURVEY_CONFIGURATION:
        {
            guint8  cnt;
            guint8  i;

            cnt = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_scan_mask_cnt, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            for (i = 0; i < cnt; i++)
            {
              proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_scan_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
              offset += 4;
            }

            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_conf_mask, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            break;
        }
        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the Beacon Survey Response.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static guint
dissect_zdp_rsp_beacon_survey_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  type;
    guint8  length;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_rsp_beacon_survey, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
        case ZBEE_TLV_TYPE_BEACON_SURVEY_CONFIGURATION:
        {
            guint8  cnt;
            guint8  i;

            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_conf_mask, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            cnt = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_scan_mask_cnt, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            for (i = 0; i < cnt; i++)
            {
              proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_scan_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
              offset += 4;
            }

            break;
        }

        case ZBEE_TLV_TYPE_BEACON_SURVEY_RESULTS:
        {
            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_total, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_cur_zbn, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_cur_zbn_potent_parents, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_other_zbn, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            break;
        }

        case ZBEE_TLV_TYPE_BEACON_SURVEY_POTENTIAL_PARENTS:
            offset = dissect_zbee_tlv_potential_parents(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the Security Challenge Request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static guint
dissect_zdp_req_security_challenge_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  type;
    guint8  length;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_req_challenge, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
       case 0:
       {
           proto_tree_add_item(tree, hf_zbee_tlv_local_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
           offset += 8;

           proto_tree_add_item(tree, hf_zbee_tlv_challenge_value, tvb, offset, 8, ENC_NA);
           offset += 8;
           break;
       }
       default:
           proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
           offset += length;
           break;
    }

    return offset;
}

/*
 *Helper dissector for the Security Challenge Response.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static guint
dissect_zdp_rsp_security_challenge_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  type;
    guint8  length;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_rsp_challenge, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
       case 0:
       {
           proto_tree_add_item(tree, hf_zbee_tlv_local_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
           offset += 8;

           proto_tree_add_item(tree, hf_zbee_tlv_challenge_value, tvb, offset, 8, ENC_NA);
           offset += 8;

           proto_tree_add_item(tree, hf_zbee_tlv_aps_frame_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
           offset += 4;

           proto_tree_add_item(tree, hf_zbee_tlv_challenge_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
           offset += 4;

           proto_tree_add_item(tree, hf_zbee_tlv_mic64, tvb, offset, 8, ENC_NA);
           offset += 8;
           break;
       }
       default:
           proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
           offset += length;
           break;
    }

    return offset;
}


/*
 *Helper dissector for the Security Challenge Response.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static guint
dissect_zdp_rsp_security_set_configuration_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
  guint8  type;
  guint8  length;

  type = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_zbee_tlv_local_type_rsp_set_configuration, tvb, offset, 1, ENC_NA);
  offset += 1;

  length = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
  offset += 1;

  length += 1;
  switch (type) {
     case 0:
     {
         guint8      count;
         guint8      i;

         count = tvb_get_guint8(tvb, offset);
         proto_tree_add_item(tree, hf_zbee_zdp_tlv_status_count, tvb, offset, 1, ENC_NA);
         offset += 1;

         for (i = 0; i < count; i++)
         {
             proto_tree_add_item(tree, hf_zbee_zdp_tlv_type_id, tvb, offset, 1, ENC_NA);
             offset += 1;
             proto_tree_add_item(tree, hf_zbee_zdp_tlv_proc_status, tvb, offset, 1, ENC_NA);
             offset += 1;
         }
         break;
     }
     default:
         proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
         offset += length;
         break;
  }

  return offset;
}


/*
 *Helper dissector for the Security Start Key Negotiation req/rsp
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static guint
dissect_zdp_security_start_key_neg_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  type;
    guint8  length;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_key_negotiation_req_rsp, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1; /* actual length */

    switch (type) {

       case ZBEE_TLV_TYPE_KEY_NEG_REQ_CURVE25519_PUBLIC_POINT:
           offset = dissect_zbee_tlv_curve25519_public_point(tvb, pinfo, tree, offset);
           break;

       default:
           proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
           offset += length;
           break;
    }

    return offset;
}

/*
 *Helper dissector for the Security Start Key Update req/rsp
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static guint
dissect_zdp_security_key_upd_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
  guint8  type;
      guint8  length;

      type = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(tree, hf_zbee_tlv_local_type_key_update_req_rsp, tvb, offset, 1, ENC_NA);
      offset += 1;

      length = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
      offset += 1;

      length += 1; /* actual length */

      switch (type) {

         case ZBEE_TLV_TYPE_KEY_UPD_REQ_SELECTED_KEY_NEGOTIATION_METHOD:
             offset = dissect_zbee_tlv_selected_key_negotiation_method(tvb, pinfo, tree, offset);
             break;

         default:
             proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
             offset += length;
             break;
      }

      return offset;
}
/*
 *Helper dissector for the Security Get Auth Level Response.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static guint
dissect_zdp_rsp_security_get_auth_level_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  type;
    guint8  length;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_get_auth_level_rsp, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
       case ZBEE_TLV_TYPE_GET_AUTH_LEVEL:
           offset = dissect_zbee_tlv_device_auth_level(tvb, pinfo, tree, offset);
           break;

       default:
           proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
           offset += length;
           break;
    }

    return offset;
}


/*
 *Helper dissector for the ZDP commands.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@param  cmd_id - ZDP command id .
 *@return offset after command dissection.
*/
static guint
dissect_zdp_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, guint cmd_id)
{
    guint8  total_tlv_length = 2 /*type + len fields*/ + tvb_get_guint8(tvb, offset + 1) + 1;
    guint8  tmp_offset = offset;

    switch (cmd_id) {
        case ZBEE_ZDP_REQ_CLEAR_ALL_BINDINGS:
            offset = dissect_zdp_req_clear_all_bindings_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_REQ_SECURITY_START_KEY_UPDATE:
        case ZBEE_ZDP_RSP_SECURITY_START_KEY_UPDATE:
        case ZBEE_ZDP_RSP_NODE_DESC:
            offset = dissect_zdp_security_key_upd_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_REQ_SECURITY_START_KEY_NEGOTIATION:
        case ZBEE_ZDP_RSP_SECURITY_START_KEY_NEGOTIATION:
            offset = dissect_zdp_security_start_key_neg_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_REQ_SECURITY_GET_AUTH_TOKEN:
            offset = dissect_zdp_req_security_get_auth_token_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_REQ_SECURITY_GET_AUTH_LEVEL:
            offset = dissect_zdp_req_security_get_auth_level_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_REQ_SECURITY_DECOMMISSION:
            offset = dissect_zdp_req_security_decommission_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_RSP_SECURITY_GET_AUTH_LEVEL:
            offset = dissect_zdp_rsp_security_get_auth_level_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_REQ_MGMT_NWK_BEACON_SURVEY:
            offset = dissect_zdp_req_beacon_survey_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_RSP_MGMT_NWK_BEACON_SURVEY:
            offset = dissect_zdp_rsp_beacon_survey_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_REQ_SECURITY_CHALLENGE:
            offset = dissect_zdp_req_security_challenge_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_RSP_SECURITY_CHALLENGE:
            offset = dissect_zdp_rsp_security_challenge_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_RSP_SECURITY_SET_CONFIGURATION:
            offset = dissect_zdp_rsp_security_set_configuration_local_tlv(tvb, pinfo, tree, offset);
            break;
        default:
        {
            offset = dissect_unknown_tlv(tvb, pinfo, tree, offset);
            break;
        }
    }

    /* check extra bytes */
    if ((offset - tmp_offset) < total_tlv_length)
    {
      proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, total_tlv_length - 2, ENC_NA);
      offset = tmp_offset + total_tlv_length;
    }

    return offset;
}

/**
 * *Dissector for Zigbee Manufacturer Specific Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@param  length of TLV data
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_manufacturer_specific(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, guint8 length)
{
    proto_tree_add_item(tree, hf_zbee_tlv_manufacturer_specific, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length - 2, ENC_NA);
    offset += length - 2;

    return offset;
} /* dissect_zbee_tlv_manufacturer_specific */

/**
 *Dissector for Zigbee Supported Key Negotiation Methods Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_supported_key_negotiation_methods(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    static int * const supported_key_negotiation_methods[] = {
        &hf_zbee_tlv_supported_key_negotiation_methods_key_request,
        &hf_zbee_tlv_supported_key_negotiation_methods_ecdhe_using_curve25519_aes_mmo128,
        &hf_zbee_tlv_supported_key_negotiation_methods_ecdhe_using_curve25519_sha256,
        NULL
    };

    static int * const supported_secrets[] = {
        &hf_zbee_tlv_supported_preshared_secrets_auth_token,
        &hf_zbee_tlv_supported_preshared_secrets_ic,
        &hf_zbee_tlv_supported_preshared_secrets_passcode_pake,
        &hf_zbee_tlv_supported_preshared_secrets_basic_access_key,
        &hf_zbee_tlv_supported_preshared_secrets_admin_access_key,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_tlv_supported_key_negotiation_methods, ett_zbee_tlv_supported_key_negotiation_methods, supported_key_negotiation_methods, ENC_NA);
    offset += 1;

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_tlv_supported_secrets, ett_zbee_tlv_supported_secrets, supported_secrets, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_zbee_tlv_device_eui64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
} /* dissect_zbee_tlv_supported_key_negotiation_methods */

/**
 *Dissector for Zigbee PAN ID conflict report Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_panid_conflict_report(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_panid_conflict_cnt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}


/**
 * *Dissector for Zigbee Configuration Parameters Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_configuration_parameters(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    static int * const bitmask[] = {
        &hf_zbee_tlv_configuration_param_restricted_mode,
        &hf_zbee_tlv_configuration_param_link_key_enc,
        &hf_zbee_tlv_configuration_param_leave_req_allowed,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_tlv_configuration_param, ett_zbee_tlv_configuration_param, bitmask, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
} /* dissect_zbee_tlv_configuration_parameters */


/**
 * *Dissector for Zigbee Configuration Parameters Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_dev_cap_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    static int * const bitmask[] = {
        &hf_zbee_tlv_dev_cap_ext_zbdirect_virt_device,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_tlv_dev_cap_ext_capability_information, ett_zbee_tlv_capability_information, bitmask, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
} /* dissect_zbee_tlv_configuration_parameters */

/**
 * *Dissector for Zigbee CPotential Parents Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_potential_parents(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
  guint8 count, i;

  proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_current_parent, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_zbee_tlv_lqa, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  count = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_cnt_parents, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  for (i = 0; i < count; i++)
  {
    proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_parent, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_zbee_tlv_lqa, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
  }

  return offset;
}

/**
 * *Dissector for Zigbee Next PAN ID Change Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_next_pan_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_next_pan_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
} /* dissect_zbee_tlv_next_pan_id */

/**
 * *Dissector for Zigbee Next Channel Change Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_next_channel_change(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    /* todo: fix this (do channel mask) */
    proto_tree_add_item(tree, hf_zbee_tlv_next_channel_change, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
} /* dissect_zbee_tlv_next_channel_change */

/**
 * *Dissector for Zigbee Passphrase Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_passphrase(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_passphrase, tvb, offset, 16, ENC_NA);
    offset += 16;

    return offset;
} /* dissect_zbee_tlv_passphrase */


/**
 * *Dissector for Zigbee Router Information Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_router_information(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    static int * const router_information[] = {
        &hf_zbee_tlv_router_information_hub_connectivity,
        &hf_zbee_tlv_router_information_uptime,
        &hf_zbee_tlv_router_information_pref_parent,
        &hf_zbee_tlv_router_information_battery_backup,
        &hf_zbee_tlv_router_information_enhanced_beacon_request_support,
        &hf_zbee_tlv_router_information_mac_data_poll_keepalive_support,
        &hf_zbee_tlv_router_information_end_device_keepalive_support,
        &hf_zbee_tlv_router_information_power_negotiation_support,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_tlv_router_information, ett_zbee_tlv_router_information, router_information, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
} /* dissect_zbee_tlv_router_information */

/**
 * *Dissector for Zigbee Fragmentation Parameters Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_fragmentation_parameters(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_node_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_zbee_tlv_frag_opt, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_zbee_tlv_max_reassembled_buf_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
} /* dissect_zbee_tlv_fragmentation_parameters */

/**
 *Dissector for Zigbee Selected Key Negotiation Methods TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_selected_key_negotiation_method(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_selected_key_negotiation_method, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_zbee_tlv_selected_pre_shared_secret, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_zbee_tlv_device_eui64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
} /* dissect_zbee_tlv_selected_key_negotiation_methods */


/**
 *Dissector for Curve25519 Public Point TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_curve25519_public_point(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_device_eui64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_zbee_tlv_curve25519_public_point, tvb, offset, 32, ENC_NA);
    offset += 32;

    return offset;
} /* dissect_zbee_tlv_curve25519_public_point */

/*
 *Dissector for Security Decommission Req EUI64 TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_eui64(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8 eui64_count;
    guint8 i;

    eui64_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_count, tvb, offset, 1, ENC_NA);
    offset += 1;

    for (i = 0; i < eui64_count; i++)
    {
        proto_tree_add_item(tree, hf_zbee_tlv_device_eui64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }

    return offset;
}

/*
 *Dissector for Clear All Bindings Req EUI64 TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_clear_all_bindigs_eui64(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    return dissect_zbee_tlv_eui64(tvb, pinfo, tree, offset);
}

/*
 *Dissector for Requested Authentication Token ID TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_requested_auth_token_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_global_tlv_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

/*
 *Dissector for Target IEEE Address TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_target_ieee_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

/**
 * *Dissector for Device Authentication Level TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv_device_auth_level(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{

    proto_tree_add_item(tree, hf_zbee_tlv_local_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_zbee_tlv_local_initial_join_method, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_zbee_tlv_local_active_lk_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
} /* dissect_zbee_tlv_device_auth_level */

/*
 * ToDo: descr
 */
static guint
dissect_global_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
    guint8  type;
    guint8  length;
    guint   tmp_offset;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_global_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    tmp_offset = offset;
    switch (type) {
        case ZBEE_TLV_TYPE_MANUFACTURER_SPECIFIC:
            offset = dissect_zbee_tlv_manufacturer_specific(tvb, pinfo, tree, offset, length);
            break;

        case ZBEE_TLV_TYPE_SUPPORTED_KEY_NEGOTIATION_METHODS:
            offset = dissect_zbee_tlv_supported_key_negotiation_methods(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_PANID_CONFLICT_REPORT:
            offset = dissect_zbee_tlv_panid_conflict_report(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_NEXT_PAN_ID:
            offset = dissect_zbee_tlv_next_pan_id(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_NEXT_CHANNEL_CHANGE:
            offset = dissect_zbee_tlv_next_channel_change(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_PASSPHRASE:
            offset = dissect_zbee_tlv_passphrase(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_ROUTER_INFORMATION:
            offset = dissect_zbee_tlv_router_information(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_FRAGMENTATION_PARAMETERS:
            offset = dissect_zbee_tlv_fragmentation_parameters(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_JOINER_ENCAPSULATION_GLOBAL:
            offset = dissect_zbee_tlvs(tvb, pinfo, tree, offset, NULL, ZBEE_TLV_SRC_TYPE_DEFAULT, 0);
            break;

        case ZBEE_TLV_TYPE_BEACON_APPENDIX_ENCAPSULATION_GLOBAL:
            offset = dissect_zbee_tlvs(tvb, pinfo, tree, offset, NULL, ZBEE_TLV_SRC_TYPE_DEFAULT, 0);
            break;

        case ZBEE_TLV_TYPE_CONFIGURATION_MODE_PARAMETERS:
            offset = dissect_zbee_tlv_configuration_parameters(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_DEVICE_CAPABILITY_EXTENSION:
            offset = dissect_zbee_tlv_dev_cap_ext(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    /* check extra bytes */
    if ((offset - tmp_offset) < length)
    {
      proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
      offset = tmp_offset + length;
    }

    return offset;
}

/**
 *Dissector for Unknown Zigbee TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_unknown_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset)
{
  guint8       length;

  proto_tree_add_item(tree, hf_zbee_tlv_type, tvb, offset, 1, ENC_NA);
  offset += 1;

  length = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
  offset += 1;

  length += 1; /* length of tlv_val == tlv_len + 1 */
  proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
  offset += length;

  return offset;
}

/**
 *Dissector for Zigbee TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static guint
dissect_zbee_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, void *data, guint8 source_type, guint cmd_id)
{
    guint8       type;

    type = tvb_get_guint8(tvb, offset);

    if (type >= ZBEE_TLV_GLOBAL_START_NUMBER)
    {
        offset = dissect_global_tlv (tvb, pinfo, tree, offset);
    }
    else
    {
        switch (source_type)
        {
            case ZBEE_TLV_SRC_TYPE_ZBEE_ZDP:
                offset = dissect_zdp_local_tlv(tvb, pinfo, tree, offset, cmd_id);
                break;

            case ZBEE_TLV_SRC_TYPE_ZBEE_APS:
                offset = dissect_aps_local_tlv(tvb, pinfo, tree, offset, data, cmd_id);
                break;

            default:
                offset = dissect_unknown_tlv(tvb, pinfo, tree, offset);
                break;
        }
    }

    return offset;
} /* dissect_zbee_tlv */

/**
 *Dissector for Zigbee TLVs
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@param  source_type ToDo:
 *@param  cmd_id ToDo:
 *@return offset after command dissection.
 */
guint
dissect_zbee_tlvs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, void *data, guint8 source_type, guint cmd_id)
{
    proto_tree  *subtree;
    guint8       length;

    while (tvb_bytes_exist(tvb, offset, ZBEE_TLV_HEADER_LENGTH)) {
        length = tvb_get_guint8(tvb, offset + 1) + 1;
        subtree = proto_tree_add_subtree(tree, tvb, offset, ZBEE_TLV_HEADER_LENGTH + length, ett_zbee_tlv, NULL, "TLV");
        offset = dissect_zbee_tlv(tvb, pinfo, subtree, offset, data, source_type, cmd_id);
    }

    return offset;
} /* dissect_zbee_tlvs */

/**
 * Dissector for ZBEE TLV.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to data tree wireshark uses to display packet.
 */
static int
dissect_zbee_tlv_default(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  guint offset = 0;

  offset = dissect_zbee_tlvs(tvb, pinfo, tree, offset, data, ZBEE_TLV_SRC_TYPE_DEFAULT, 0);

  /* Check for leftover bytes. */
  if (offset < tvb_captured_length(tvb)) {
      /* Bytes leftover! */
      tvbuff_t    *leftover_tvb   = tvb_new_subset_remaining(tvb, offset);
      /* Dump the leftover to the data dissector. */
      call_data_dissector(leftover_tvb, pinfo, tree);
  }

  return tvb_captured_length(tvb);
}

/**
 * Proto ZBOSS Network Coprocessor product registration routine
 */
void proto_register_zbee_tlv(void)
{
    /* NCP protocol headers */
    static hf_register_info hf[] = {
        { &hf_zbee_tlv_relay_msg_type,
        { "Type", "zbee_tlv.relay.type", FT_UINT8, BASE_HEX, VALS(zbee_aps_relay_tlvs), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_relay_msg_length,
        { "Length", "zbee_tlv.relay.length", FT_UINT8, BASE_DEC, NULL, 0x0,  NULL, HFILL }},

        { &hf_zbee_tlv_relay_msg_joiner_ieee,
        { "Joiner IEEE",        "zbee_tlv.relay.joiner_ieee", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_global_type,
          { "Type",        "zbee_tlv.type_global", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_global_types), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_key_update_req_rsp,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_key_update_req_rsp), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_key_negotiation_req_rsp,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_key_negotiation_req_rsp), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_get_auth_level_rsp,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_get_auth_level_rsp), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_clear_all_bindings_req,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_clear_all_bindings_req), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_req_security_get_auth_token,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_req_security_get_auth_token), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_req_security_get_auth_level,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_req_security_get_auth_level), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_req_security_decommission,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_req_security_decommission), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_req_beacon_survey,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_req_beacon_survey), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_rsp_beacon_survey,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_rsp_beacon_survey), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_req_challenge,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_req_challenge), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_rsp_challenge,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_rsp_challenge), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_rsp_set_configuration,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_rsp_set_configuration), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_type,
          { "Unknown Type", "zbee_tlv.type", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_length,
          { "Length",      "zbee_tlv.length", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_value,
          { "Value",       "zbee_tlv.value", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_count,
          { "Count",       "zbee_tlv.count", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_tlv_status_count,
            { "TLV Status Count",           "zbee_tlv.tlv_status_count", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_tlv_type_id,
            { "TLV Type ID",                "zbee_tlv.tlv_type_id", FT_UINT8, BASE_HEX, VALS(zbee_tlv_global_types), 0x0,
            NULL, HFILL }},

        { &hf_zbee_zdp_tlv_proc_status,
            { "TLV Processing Status",      "zbee_tlv.tlv_proc_status", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_manufacturer_specific,
          { "ZigBee Manufacturer ID", "zbee_tlv.manufacturer_specific", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_supported_key_negotiation_methods,
          { "Supported Key Negotiation Methods", "zbee_tlv.supported_key_negotiation_methods", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_supported_key_negotiation_methods_key_request,
          { "Key Request (ZigBee 3.0)",             "zbee_tlv.supported_key_negotiation_methods.key_request", FT_BOOLEAN, 8, NULL,
            ZBEE_TLV_SUPPORTED_KEY_NEGOTIATION_METHODS_KEY_REQUEST, NULL, HFILL }},

        { &hf_zbee_tlv_supported_key_negotiation_methods_ecdhe_using_curve25519_aes_mmo128,
          { "ECDHE using Curve25519 with Hash AES-MMO-128", "zbee_tlv.supported_key_negotiation_methods.ecdhe_using_curve25519_aes_mmo128", FT_BOOLEAN, 8, NULL,
            ZBEE_TLV_SUPPORTED_KEY_NEGOTIATION_METHODS_ANONYMOUS_ECDHE_USING_CURVE25519_AES_MMO128, NULL, HFILL }},

        { &hf_zbee_tlv_supported_key_negotiation_methods_ecdhe_using_curve25519_sha256,
          { "ECDHE using Curve25519 with Hash SHA-256", "zbee_tlv.supported_key_negotiation_methods.ecdhe_using_curve25519_sha256", FT_BOOLEAN, 8, NULL,
            ZBEE_TLV_SUPPORTED_KEY_NEGOTIATION_METHODS_ANONYMOUS_ECDHE_USING_CURVE25519_SHA256, NULL, HFILL }},

        { &hf_zbee_tlv_supported_secrets,
          { "Supported Pre-shared Secrets Bitmask", "zbee_tlv.supported_secrets", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_supported_preshared_secrets_auth_token,
          { "Symmetric Authentication Token", "zbee_tlv.supported_secrets.auth_token", FT_BOOLEAN, 8, NULL,
            0x1, NULL, HFILL }},

        { &hf_zbee_tlv_supported_preshared_secrets_ic,
          { "128-bit pre-configured link-key from install code", "zbee_tlv.supported_secrets.ic", FT_BOOLEAN, 8, NULL,
            0x2, NULL, HFILL }},

        { &hf_zbee_tlv_supported_preshared_secrets_passcode_pake,
          { "Variable-length pass code for PAKE protocols", "zbee_tlv.supported_secrets.passcode_pake", FT_BOOLEAN, 8, NULL,
            0x4, NULL, HFILL }},

        { &hf_zbee_tlv_supported_preshared_secrets_basic_access_key,
          { "Basic Access Key", "zbee_tlv.supported_secrets.basic_key", FT_BOOLEAN, 8, NULL,
            0x8, NULL, HFILL }},

        { &hf_zbee_tlv_supported_preshared_secrets_admin_access_key,
          { "Administrative Access Key", "zbee_tlv.supported_secrets.admin_key", FT_BOOLEAN, 8, NULL,
            0x10, NULL, HFILL }},

        { &hf_zbee_tlv_panid_conflict_cnt,
          { "PAN ID Conflict Count", "zbee_tlv.panid_conflict_cnt", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_next_pan_id,
          { "Next PAN ID Change", "zbee_tlv.next_pan_id", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_next_channel_change,
          { "Next Channel Change", "zbee_tlv.next_channel", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_passphrase,
          { "128-bit Symmetric Passphrase", "zbee_tlv.passphrase", FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_challenge_value,
          { "Challenge Value", "zbee_tlv.challenge_val", FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_aps_frame_counter,
          { "APS Frame Counter", "zbee_tlv.aps_frame_cnt", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_challenge_counter,
          { "Challenge Counter", "zbee_tlv.challenge_cnt", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_configuration_param,
          { "Configuration Parameters", "zbee_tlv.configuration_parameters", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_configuration_param_restricted_mode,
          { "apsZdoRestrictedMode", "zbee_tlv.conf_param.restricted_mode", FT_UINT16, BASE_DEC, NULL,
            0x1, NULL, HFILL }},

        { &hf_zbee_tlv_configuration_param_link_key_enc,
          { "requireLinkKeyEncryptionForApsTransportKey", "zbee_tlv.conf_param.req_link_key_enc", FT_UINT16, BASE_DEC, NULL,
            0x2, NULL, HFILL }},

        { &hf_zbee_tlv_configuration_param_leave_req_allowed,
          { "nwkLeaveRequestAllowed", "zbee_tlv.conf_param.leave_req_allowed", FT_UINT16, BASE_DEC, NULL,
            0x4, NULL, HFILL }},

        { &hf_zbee_tlv_dev_cap_ext_capability_information,
          { "Capability Information", "zbee_tlv.dev_cap_ext_cap_info", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_dev_cap_ext_zbdirect_virt_device,
          { "Zigbee Direct Virtual Device", "zbee_tlv.dev_cap_ext.zbdirect_virt_dev", FT_UINT16, BASE_DEC, NULL,
            0x1, NULL, HFILL }},

        { &hf_zbee_tlv_lqa,
          { "LQA", "zbee_tlv.lqa", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_router_information,
          { "Router Information", "zbee_tlv.router_information", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_hub_connectivity,
          { "Hub Connectivity",   "zbee_tlv.router_information.hub_connectivity", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_HUB_CONNECTIVITY, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_uptime,
          { "Uptime",             "zbee_tlv.router_information.uptime", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_UPTIME, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_pref_parent,
          { "Preferred parent",        "zbee_tlv.router_information.pref_parent", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_PREF_PARENT, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_battery_backup,
          { "Battery Backup",     "zbee_tlv.router_information.battery", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_BATTERY_BACKUP, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_enhanced_beacon_request_support,
          { "Enhanced Beacon Request Support", "zbee_tlv.router_information.enhanced_beacon", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_ENHANCED_BEACON_REQUEST_SUPPORT, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_mac_data_poll_keepalive_support,
          { "MAC Data Poll Keepalive Support", "zbee_tlv.router_information.mac_data_poll_keepalive", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_MAC_DATA_POLL_KEEPALIVE_SUPPORT, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_end_device_keepalive_support,
          { "End Device Keepalive Support", "zbee_tlv.router_information.end_dev_keepalive", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_END_DEVICE_KEEPALIVE_SUPPORT, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_power_negotiation_support,
          { "Power Negotiation Support", "zbee_tlv.router_information.power_negotiation", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_POWER_NEGOTIATION_SUPPORT, NULL, HFILL }},

        { &hf_zbee_tlv_node_id,
          { "Node ID", "zbee_tlv.node_id", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_frag_opt,
          { "Fragmentation Options", "zbee_tlv.frag_opt", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_max_reassembled_buf_size,
          { "Maximum Reassembled Input Buffer Size", "zbee_tlv.max_buf_size", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_selected_key_negotiation_method,
          { "Selected Key Negotiation Method", "zbee_tlv.selected_key_negotiation_method", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_selected_key_negotiation_method), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_selected_pre_shared_secret,
          { "Selected Pre Shared Secret", "zbee_tlv.selected_pre_shared_secret", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_selected_pre_shared_secret), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_device_eui64,
          { "Device EUI64", "zbee_tlv.device_eui64", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_curve25519_public_point,
          { "Curve25519 Public Point", "zbee_tlv.curve25519_public_point", FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_global_tlv_id,
          { "TLV Type ID", "zbee_tlv.global_tlv_id", FT_UINT8, BASE_HEX, VALS(zbee_tlv_global_types), 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_local_ieee_addr,
          { "IEEE Addr", "zbee_tlv.ieee_addr", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_mic64,
          { "MIC", "zbee_tlv.mic64", FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_local_initial_join_method,
          { "Initial Join Method",        "zbee_tlv.init_method", FT_UINT8, BASE_HEX,
            VALS(zbee_initial_join_methods), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_active_lk_type,
          { "Active link key type",        "zbee_tlv.lk_type", FT_UINT8, BASE_HEX,
            VALS(zbee_active_lk_types), 0x0, NULL, HFILL }},
    };

    /* Protocol subtrees */
    static gint *ett[] =
        {
            &ett_zbee_aps_tlv,
            &ett_zbee_aps_relay,
            &ett_zbee_tlv,
            &ett_zbee_tlv_supported_key_negotiation_methods,
            &ett_zbee_tlv_supported_secrets,
            &ett_zbee_tlv_router_information,
            &ett_zbee_tlv_configuration_param,
            &ett_zbee_tlv_capability_information,
        };

    proto_zbee_tlv = proto_register_protocol("Zigbee TLV", "ZB TLV", "zbee_tlv");

    proto_register_field_array(proto_zbee_tlv, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("zbee_tlv", dissect_zbee_tlv_default, proto_zbee_tlv);
} /* proto_register_zbee_tlv */
