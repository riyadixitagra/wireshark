/* packet-json_3gpp.c
 * Routines for JSON dissection - 3GPP Extension
 *
 * References:
 * - 3GPP TS 24.301
 * - 3GPP TS 24.501
 * - 3GPP TS 29.274
 * - 3GPP TS 29.571
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This dissector registers a dissector table for 3GPP Vendor specific
 * keys which will be called from the JSON dissector to dissect
 * the content of keys of the OctetString type(or similar).
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/tvbparse.h>
#include <epan/proto_data.h>

#include "packet-gtpv2.h"
#include "packet-gsm_a_common.h"
#include "packet-json.h"

void proto_register_json_3gpp(void);

static int proto_json_3gpp = -1;

static gint ett_json_base64decoded_eps_ie = -1;
static gint ett_json_base64decoded_nas5g_ie = -1;
static gint ett_json_3gpp_data = -1;

static int hf_json_3gpp_binary_data = -1;

static int hf_json_3gpp_ueepspdnconnection = -1;
static int hf_json_3gpp_bearerlevelqos = -1;
static int hf_json_3gpp_epsbearersetup = -1;
static int hf_json_3gpp_forwardingbearercontexts = -1;
static int hf_json_3gpp_forwardingfteid = -1;
static int hf_json_3gpp_pgwnodename = -1;
static int hf_json_3gpp_pgws8cfteid = -1;
static int hf_json_3gpp_pgws8ufteid = -1;
static int hf_json_3gpp_qosrules = -1;
static int hf_json_3gpp_qosflowdescription = -1;
static int hf_json_3gpp_suppFeat = -1;


static int hf_json_3gpp_suppfeat = -1;
static int hf_json_3gpp_suppfeat_npcf_1_tsc = -1;
static int hf_json_3gpp_suppfeat_npcf_2_resshare = -1;
static int hf_json_3gpp_suppfeat_npcf_3_3gpppsdataoff = -1;
static int hf_json_3gpp_suppfeat_npcf_4_adc = -1;

static int hf_json_3gpp_suppfeat_npcf_5_umc = -1;
static int hf_json_3gpp_suppfeat_npcf_6_netloc = -1;
static int hf_json_3gpp_suppfeat_npcf_7_rannascause = -1;
static int hf_json_3gpp_suppfeat_npcf_8_provafsignalflow = -1;

static int hf_json_3gpp_suppfeat_npcf_9_pcscfrestorationenhancement = -1;
static int hf_json_3gpp_suppfeat_npcf_10_pra = -1;
static int hf_json_3gpp_suppfeat_npcf_11_ruleversioning = -1;
static int hf_json_3gpp_suppfeat_npcf_12_sponsoredconnectivity = -1;

static int hf_json_3gpp_suppfeat_npcf_13_ransupportinfo = -1;
static int hf_json_3gpp_suppfeat_npcf_14_policyupdatewhenuesuspends = -1;
static int hf_json_3gpp_suppfeat_npcf_15_accesstypecondition = -1;
static int hf_json_3gpp_suppfeat_npcf_16_multiipv6addrprefix = -1;

static int hf_json_3gpp_suppfeat_npcf_17_sessionruleerrorhandling = -1;
static int hf_json_3gpp_suppfeat_npcf_18_af_charging_identifier = -1;
static int hf_json_3gpp_suppfeat_npcf_19_atsss = -1;
static int hf_json_3gpp_suppfeat_npcf_20_pendingtransaction = -1;

static int hf_json_3gpp_suppfeat_npcf_21_urllc = -1;
static int hf_json_3gpp_suppfeat_npcf_22_macaddressrange = -1;
static int hf_json_3gpp_suppfeat_npcf_23_wwc = -1;
static int hf_json_3gpp_suppfeat_npcf_24_qosmonitoring = -1;

static int hf_json_3gpp_suppfeat_npcf_25_authorizationwithrequiredqos = -1;
static int hf_json_3gpp_suppfeat_npcf_26_enhancedbackgrounddatatransfer = -1;
static int hf_json_3gpp_suppfeat_npcf_27_dn_authorization = -1;
static int hf_json_3gpp_suppfeat_npcf_28_pdusessionrelcause = -1;

static int hf_json_3gpp_suppfeat_npcf_29_samepcf = -1;
static int hf_json_3gpp_suppfeat_npcf_30_adcmultiredirection = -1;
static int hf_json_3gpp_suppfeat_npcf_31_respbasedsessionrel = -1;
static int hf_json_3gpp_suppfeat_npcf_32_timesensitivenetworking = -1;

static int hf_json_3gpp_suppfeat_npcf_33_emdbv = -1;
static int hf_json_3gpp_suppfeat_npcf_34_dnnselectionmode = -1;
static int hf_json_3gpp_suppfeat_npcf_35_epsfallbackreport = -1;
static int hf_json_3gpp_suppfeat_npcf_36_policydecisionerrorhandling = -1;

static int hf_json_3gpp_suppfeat_npcf_37_ddneventpolicycontrol = -1;
static int hf_json_3gpp_suppfeat_npcf_38_reallocationofcredit = -1;
static int hf_json_3gpp_suppfeat_npcf_39_bdtpolicyrenegotiation = -1;
static int hf_json_3gpp_suppfeat_npcf_40_extpolicydecisionerrorhandling = -1;

static int hf_json_3gpp_suppfeat_npcf_41_immediatetermination = -1;
static int hf_json_3gpp_suppfeat_npcf_42_aggregateduelocchanges = -1;
static int hf_json_3gpp_suppfeat_npcf_43_es3xx = -1;
static int hf_json_3gpp_suppfeat_npcf_44_groupidlistchange = -1;

static int hf_json_3gpp_suppfeat_npcf_45_disableuenotification = -1;
static int hf_json_3gpp_suppfeat_npcf_46_offlinechonly = -1;
static int hf_json_3gpp_suppfeat_npcf_47_dual_connectivity_redundant_up_paths = -1;
static int hf_json_3gpp_suppfeat_npcf_48_ddneventpolicycontrol2 = -1;

static int hf_json_3gpp_suppfeat_npcf_49_vplmn_qos_control = -1;
static int hf_json_3gpp_suppfeat_npcf_50_2g3giwk = -1;
static int hf_json_3gpp_suppfeat_npcf_51_timesensitivecommunication = -1;
static int hf_json_3gpp_suppfeat_npcf_52_enedge = -1;

static int hf_json_3gpp_suppfeat_npcf_53_satbackhaulcategorychg = -1;
static int hf_json_3gpp_suppfeat_npcf_54_chfsetsupport = -1;
static int hf_json_3gpp_suppfeat_npcf_55_enatssss = -1;
static int hf_json_3gpp_suppfeat_npcf_56_mpsfordts = -1;

static int hf_json_3gpp_suppfeat_npcf_57_routinginforemoval = -1;
static int hf_json_3gpp_suppfeat_npcf_58_epra = -1;
static int hf_json_3gpp_suppfeat_npcf_59_aminfluence = -1;
static int hf_json_3gpp_suppfeat_npcf_60_pvssupport = -1;

static int hf_json_3gpp_suppfeat_npcf_61_enena = -1;
static int hf_json_3gpp_suppfeat_npcf_62_biumr = -1;
static int hf_json_3gpp_suppfeat_npcf_63_easipreplacement = -1;
static int hf_json_3gpp_suppfeat_npcf_64_exposuretoeas = -1;

static int hf_json_3gpp_suppfeat_npcf_65_simultconnectivity = -1;
static int hf_json_3gpp_suppfeat_npcf_66_sgwrest = -1;
static int hf_json_3gpp_suppfeat_npcf_67_releasetoreactivate = -1;
static int hf_json_3gpp_suppfeat_npcf_68_easdiscovery = -1;

static int hf_json_3gpp_suppfeat_npcf_69_accnetchargid_string = -1;

/* Functions to sub dissect json content */
static void
dissect_base64decoded_eps_ie(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo, int offset, int len, const char* key_str _U_, gboolean use_compact _U_)
{
	/* base64-encoded characters, encoding the
	 * EPS IE specified in 3GPP TS 29.274.
	 */

	proto_item* ti;
	proto_tree* sub_tree;
	tvbuff_t* bin_tvb = base64_tvb_to_new_tvb(tvb, offset, len);
	int bin_tvb_length = tvb_reported_length(bin_tvb);
	add_new_data_source(pinfo, bin_tvb, "Base64 decoded");
	ti = proto_tree_add_item(tree, hf_json_3gpp_binary_data, bin_tvb, 0, bin_tvb_length, ENC_NA);
	sub_tree = proto_item_add_subtree(ti, ett_json_base64decoded_eps_ie);
	dissect_gtpv2_ie_common(bin_tvb, pinfo, sub_tree, 0, 0/* Message type 0, Reserved */, NULL);

	return;
}

static void
dissect_base64decoded_nas5g_ie(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo, int offset, int len, const char* key_str, gboolean use_compact _U_)
{
	/* base64-encoded characters, encoding the
	 * NAS-5G IE specified in 3GPP TS 24.501.
	 */
	proto_item* ti;
	proto_tree* sub_tree;
	tvbuff_t* bin_tvb = base64_tvb_to_new_tvb(tvb, offset, len);
	int bin_tvb_length = tvb_reported_length(bin_tvb);
	add_new_data_source(pinfo, bin_tvb, "Base64 decoded");
	ti = proto_tree_add_item(tree, hf_json_3gpp_binary_data, bin_tvb, 0, bin_tvb_length, ENC_NA);
	sub_tree = proto_item_add_subtree(ti, ett_json_base64decoded_nas5g_ie);

	if (strcmp(key_str, "qosRules") == 0) {
		/* qosRules
		 * This IE shall contain the QoS Rule(s) associated to the QoS flow to be sent to the UE.
		 * It shall be encoded as the Qos rules IE specified in clause 9.11.4.13 of 3GPP TS 24.501 (starting from octet 4).
		 */
		de_nas_5gs_sm_qos_rules(bin_tvb, sub_tree, pinfo, 0, bin_tvb_length, NULL, 0);
	}
	else if (strcmp(key_str, "qosFlowDescription") == 0) {
		/* qosFlowDescription
		 * When present, this IE shall contain the description of the QoS Flow level Qos parameters to be sent to the UE.
		 * It shall be encoded as the Qos flow descriptions IE specified in clause 9.11.4.12 of 3GPP TS 24.501 (starting from octet 1),
		 * encoding one single Qos flow description for the QoS flow to be set up.
		 */
		elem_telv(bin_tvb, sub_tree, pinfo, (guint8) 0x79, 18 /* NAS_5GS_PDU_TYPE_SM */, 11 /* DE_NAS_5GS_SM_QOS_FLOW_DES */, 0, bin_tvb_length, NULL);
	}

	return;
}

static void
dissect_3gpp_supportfeatures(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_, int offset, int len, const char* key_str _U_, gboolean use_compact)
{
	/* TS 29.571 ch5.2.2
	 * A string used to indicate the features supported by an API that is used as defined in clause 6.6 in 3GPP TS 29.500 [25].
	 * The string shall contain a bitmask indicating supported features in hexadecimal representation:
	 * Each character in the string shall take a value of "0" to "9", "a" to "f" or "A" to "F" and
	 * shall represent the support of 4 features as described in table 5.2.2-3.
	 * The most significant character representing the highest-numbered features shall appear first in the string,
	 * and the character representing features 1 to 4 shall appear last in the string.
	 * The list of features and their numbering (starting with 1) are defined separately for each API.
	 * If the string contains a lower number of characters than there are defined features for an API,
	 * all features that would be represented by characters that are not present in the string are not supported.
	 */
	proto_item* ti;
	proto_tree* sub_tree;
	tvbuff_t   *suppfeat_tvb;

	/* Skip quotation marks */
	if (!use_compact) {
		offset++;
		len = len-2;
	}

	ti = proto_tree_add_item(tree, hf_json_3gpp_suppfeat, tvb, offset, len, ENC_ASCII);
	sub_tree = proto_item_add_subtree(ti, ett_json_3gpp_data);
	suppfeat_tvb = tvb_new_subset_length(tvb, offset, len);

	int offset_reverse = len - 1;

	/* TODO add handling of different API
	 * Idea: fetch "HTTP2 header path: /{NF}"
	 */

	static int * const json_3gpp_suppfeat_npcf_list_1[] = {
		&hf_json_3gpp_suppfeat_npcf_1_tsc,
		&hf_json_3gpp_suppfeat_npcf_2_resshare,
		&hf_json_3gpp_suppfeat_npcf_3_3gpppsdataoff,
		&hf_json_3gpp_suppfeat_npcf_4_adc,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_1, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_list_2[] = {
		&hf_json_3gpp_suppfeat_npcf_5_umc,
		&hf_json_3gpp_suppfeat_npcf_6_netloc,
		&hf_json_3gpp_suppfeat_npcf_7_rannascause,
		&hf_json_3gpp_suppfeat_npcf_8_provafsignalflow,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_2, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_list_3[] = {
		&hf_json_3gpp_suppfeat_npcf_9_pcscfrestorationenhancement,
		&hf_json_3gpp_suppfeat_npcf_10_pra,
		&hf_json_3gpp_suppfeat_npcf_11_ruleversioning,
		&hf_json_3gpp_suppfeat_npcf_12_sponsoredconnectivity,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_3, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_list_4[] = {
		&hf_json_3gpp_suppfeat_npcf_13_ransupportinfo,
		&hf_json_3gpp_suppfeat_npcf_14_policyupdatewhenuesuspends,
		&hf_json_3gpp_suppfeat_npcf_15_accesstypecondition,
		&hf_json_3gpp_suppfeat_npcf_16_multiipv6addrprefix,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_4, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_list_5[] = {
		&hf_json_3gpp_suppfeat_npcf_17_sessionruleerrorhandling,
		&hf_json_3gpp_suppfeat_npcf_18_af_charging_identifier,
		&hf_json_3gpp_suppfeat_npcf_19_atsss,
		&hf_json_3gpp_suppfeat_npcf_20_pendingtransaction,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_5, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_list_6[] = {
		&hf_json_3gpp_suppfeat_npcf_21_urllc,
		&hf_json_3gpp_suppfeat_npcf_22_macaddressrange,
		&hf_json_3gpp_suppfeat_npcf_23_wwc,
		&hf_json_3gpp_suppfeat_npcf_24_qosmonitoring,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_6, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_list_7[] = {
		&hf_json_3gpp_suppfeat_npcf_25_authorizationwithrequiredqos,
		&hf_json_3gpp_suppfeat_npcf_26_enhancedbackgrounddatatransfer,
		&hf_json_3gpp_suppfeat_npcf_27_dn_authorization,
		&hf_json_3gpp_suppfeat_npcf_28_pdusessionrelcause,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_7, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_list_8[] = {
		&hf_json_3gpp_suppfeat_npcf_29_samepcf,
		&hf_json_3gpp_suppfeat_npcf_30_adcmultiredirection,
		&hf_json_3gpp_suppfeat_npcf_31_respbasedsessionrel,
		&hf_json_3gpp_suppfeat_npcf_32_timesensitivenetworking,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_8, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_list_9[] = {
		&hf_json_3gpp_suppfeat_npcf_33_emdbv,
		&hf_json_3gpp_suppfeat_npcf_34_dnnselectionmode,
		&hf_json_3gpp_suppfeat_npcf_35_epsfallbackreport,
		&hf_json_3gpp_suppfeat_npcf_36_policydecisionerrorhandling,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_9, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_list_10[] = {
		&hf_json_3gpp_suppfeat_npcf_37_ddneventpolicycontrol,
		&hf_json_3gpp_suppfeat_npcf_38_reallocationofcredit,
		&hf_json_3gpp_suppfeat_npcf_39_bdtpolicyrenegotiation,
		&hf_json_3gpp_suppfeat_npcf_40_extpolicydecisionerrorhandling,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_10, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_list_11[] = {
		&hf_json_3gpp_suppfeat_npcf_41_immediatetermination,
		&hf_json_3gpp_suppfeat_npcf_42_aggregateduelocchanges,
		&hf_json_3gpp_suppfeat_npcf_43_es3xx,
		&hf_json_3gpp_suppfeat_npcf_44_groupidlistchange,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_11, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_list_12[] = {
		&hf_json_3gpp_suppfeat_npcf_45_disableuenotification,
		&hf_json_3gpp_suppfeat_npcf_46_offlinechonly,
		&hf_json_3gpp_suppfeat_npcf_47_dual_connectivity_redundant_up_paths,
		&hf_json_3gpp_suppfeat_npcf_48_ddneventpolicycontrol2,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_12, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_list_13[] = {
		&hf_json_3gpp_suppfeat_npcf_49_vplmn_qos_control,
		&hf_json_3gpp_suppfeat_npcf_50_2g3giwk,
		&hf_json_3gpp_suppfeat_npcf_51_timesensitivecommunication,
		&hf_json_3gpp_suppfeat_npcf_52_enedge,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_13, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_list_14[] = {
		&hf_json_3gpp_suppfeat_npcf_53_satbackhaulcategorychg,
		&hf_json_3gpp_suppfeat_npcf_54_chfsetsupport,
		&hf_json_3gpp_suppfeat_npcf_55_enatssss,
		&hf_json_3gpp_suppfeat_npcf_56_mpsfordts,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_14, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_list_15[] = {
		&hf_json_3gpp_suppfeat_npcf_57_routinginforemoval,
		&hf_json_3gpp_suppfeat_npcf_58_epra,
		&hf_json_3gpp_suppfeat_npcf_59_aminfluence,
		&hf_json_3gpp_suppfeat_npcf_60_pvssupport,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_15, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_list_16[] = {
		&hf_json_3gpp_suppfeat_npcf_61_enena,
		&hf_json_3gpp_suppfeat_npcf_62_biumr,
		&hf_json_3gpp_suppfeat_npcf_63_easipreplacement,
		&hf_json_3gpp_suppfeat_npcf_64_exposuretoeas,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_16, ENC_UTF_8|BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int* const json_3gpp_suppfeat_npcf_list_17[] = {
		&hf_json_3gpp_suppfeat_npcf_65_simultconnectivity,
		&hf_json_3gpp_suppfeat_npcf_66_sgwrest,
		&hf_json_3gpp_suppfeat_npcf_67_releasetoreactivate,
		&hf_json_3gpp_suppfeat_npcf_68_easdiscovery,
		NULL
	};
	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_17, ENC_UTF_8 | BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int* const json_3gpp_suppfeat_npcf_list_18[] = {
		&hf_json_3gpp_suppfeat_npcf_69_accnetchargid_string,
		NULL
	};

	proto_tree_add_bitmask_list(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_list_18, ENC_UTF_8 | BASE_DEC_HEX);
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	if (offset_reverse > -1) {
		proto_tree_add_format_text(sub_tree, suppfeat_tvb, 0, (offset_reverse - len));
	}

	return;
}

static void
register_static_headers(void) {

	gchar* header_name;

	/* Here hf[x].hfinfo.name is a header method which is used as key
	 * for matching ids while processing HTTP2 packets */
	static hf_register_info hf[] = {
		{
			&hf_json_3gpp_ueepspdnconnection,
			{"ueEpsPdnConnection", "json.3gpp.ueepspdnconnection",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_bearerlevelqos,
			{"bearerLevelQoS", "json.3gpp.bearerlevelqos",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_epsbearersetup,
			{"epsBearerSetup", "json.3gpp.epsbearersetup",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_forwardingbearercontexts,
			{"forwardingBearerContexts", "json.3gpp.forwardingbearercontexts",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_forwardingfteid,
			{"forwardingFTeid", "json.3gpp.forwardingfteid",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_pgwnodename,
			{"pgwNodeName", "json.3gpp.pgwnodename",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_pgws8cfteid,
			{"pgwS8cFteid", "json.3gpp.pgws8cfteid",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_pgws8ufteid,
			{"pgwS8uFteid", "json.3gpp.pgws8ufteid",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_qosrules,
			{"qosRules", "json.3gpp.qosrules",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_qosflowdescription,
			{"qosFlowDescription", "json.3gpp.qosflowdescription",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_suppFeat,
			{"suppFeat", "json.3gpp.suppFeat",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		}
	};

	/* List of decoding functions the index matches the HF */
	static void(*json_decode_fn[])(tvbuff_t * tvb, proto_tree * tree, packet_info * pinfo, int offset, int len, const char* key_str, gboolean use_compact) = {
		dissect_base64decoded_eps_ie,   /* ueEpsPdnConnection */
		dissect_base64decoded_eps_ie,   /* bearerLevelQoS */
		dissect_base64decoded_eps_ie,   /* epsBearerSetup */
		dissect_base64decoded_eps_ie,   /* forwardingBearerContexts */
		dissect_base64decoded_eps_ie,   /* forwardingFTeid */
		dissect_base64decoded_eps_ie,   /* pgwNodeName */
		dissect_base64decoded_eps_ie,   /* pgwS8cFteid */
		dissect_base64decoded_eps_ie,   /* pgwS8uFteid */

		dissect_base64decoded_nas5g_ie, /* qosRules */
		dissect_base64decoded_nas5g_ie, /* qosFlowDescription */

		dissect_3gpp_supportfeatures,

		NULL,   /* NONE */
	};

	/* Hfs with functions */
	for (guint i = 0; i < G_N_ELEMENTS(hf); ++i) {
		header_name = g_strdup(hf[i].hfinfo.name);
		json_data_decoder_t* json_data_decoder_rec = g_new(json_data_decoder_t, 1);
		json_data_decoder_rec->hf_id = &hf[i].hfinfo.id;
		json_data_decoder_rec->json_data_decoder = json_decode_fn[i];
		g_hash_table_insert(json_header_fields_hash, header_name, json_data_decoder_rec);
	}

	proto_register_field_array(proto_json_3gpp, hf, G_N_ELEMENTS(hf));
}

void
proto_register_json_3gpp(void)
{
	static hf_register_info hf[] = {

		/* 3GPP content */
		{ &hf_json_3gpp_binary_data,
			{ "Binary data", "json.binary_data",
			  FT_BYTES, BASE_NONE, NULL, 0x00,
			  "JSON binary data", HFILL }
		},
		{ &hf_json_3gpp_suppfeat,
			{ "Supported Features", "json.3gpp.suppfeat",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_1_tsc,
			{ "TSC", "json.3gpp.suppfeat.tsc",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_2_resshare,
			{ "ResShare", "json.3gpp.suppfeat.resshare",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_3_3gpppsdataoff,
			{ "3GPP-PS-Data-Off", "json.3gpp.suppfeat.3gpppsdataoff",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_4_adc,
			{ "ADC", "json.3gpp.suppfeat.adc",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_5_umc,
			{ "UMC", "json.3gpp.suppfeat.umc",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_6_netloc,
			{ "NetLoc", "json.3gpp.suppfeat.netloc",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_7_rannascause,
			{ "RAN-NAS-Cause", "json.3gpp.suppfeat.rannascause",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_8_provafsignalflow,
			{ "ProvAFsignalFlow", "json.3gpp.suppfeat.provafsignalflow",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_9_pcscfrestorationenhancement,
			{ "PCSCF-Restoration-Enhancement", "json.3gpp.suppfeat.pcscfrestorationenhancement",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_10_pra,
			{ "PRA", "json.3gpp.suppfeat.pra",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_11_ruleversioning,
			{ "RuleVersioning", "json.3gpp.suppfeat.ruleversioning",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_12_sponsoredconnectivity,
			{ "SponsoredConnectivity", "json.3gpp.suppfeat.sponsoredconnectivity",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_13_ransupportinfo,
			{ "RAN-Support-Info", "json.3gpp.suppfeat.ransupportinfo",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_14_policyupdatewhenuesuspends,
			{ "PolicyUpdateWhenUESuspends", "json.3gpp.suppfeat.policyupdatewhenuesuspends",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_15_accesstypecondition,
			{ "AccessTypeCondition", "json.3gpp.suppfeat.accesstypecondition",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_16_multiipv6addrprefix,
			{ "MultiIpv6AddrPrefix", "json.3gpp.suppfeat.multiipv6addrprefix",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_17_sessionruleerrorhandling,
			{ "SessionRuleErrorHandling", "json.3gpp.suppfeat.sessionruleerrorhandling",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_18_af_charging_identifier,
			{ "AF_Charging_Identifier", "json.3gpp.suppfeat.af_charging_identifier",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_19_atsss,
			{ "ATSSS", "json.3gpp.suppfeat.atsss",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_20_pendingtransaction,
			{ "PendingTransaction", "json.3gpp.suppfeat.pendingtransaction",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_21_urllc,
			{ "URLLC", "json.3gpp.suppfeat.urllc",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_22_macaddressrange,
			{ "MacAddressRange", "json.3gpp.suppfeat.macaddressrange",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_23_wwc,
			{ "WWC", "json.3gpp.suppfeat.wwc",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_24_qosmonitoring,
			{ "QosMonitoring", "json.3gpp.suppfeat.qosmonitoring",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_25_authorizationwithrequiredqos,
			{ "AuthorizationWithRequiredQoS", "json.3gpp.suppfeat.authorizationwithrequiredqos",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_26_enhancedbackgrounddatatransfer,
			{ "EnhancedBackgroundDataTransfer", "json.3gpp.suppfeat.enhancedbackgrounddatatransfer",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_27_dn_authorization,
			{ "DN-Authorization", "json.3gpp.suppfeat.dn_authorization",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_28_pdusessionrelcause,
			{ "PDUSessionRelCause", "json.3gpp.suppfeat.pdusessionrelcause",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_29_samepcf,
			{ "SamePcf", "json.3gpp.suppfeat.samepcf",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_30_adcmultiredirection,
			{ "ADCmultiRedirection", "json.3gpp.suppfeat.adcmultiredirection",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_31_respbasedsessionrel,
			{ "RespBasedSessionRel", "json.3gpp.suppfeat.respbasedsessionrel",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_32_timesensitivenetworking,
			{ "TimeSensitiveNetworking", "json.3gpp.suppfeat.timesensitivenetworking",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_33_emdbv,
			{ "EMDBV", "json.3gpp.suppfeat.emdbv",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_34_dnnselectionmode,
			{ "DNNSelectionMode", "json.3gpp.suppfeat.adcmultirednnselectionmodedirection",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_35_epsfallbackreport,
			{ "EPSFallbackReport", "json.3gpp.suppfeat.epsfallbackreport",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_36_policydecisionerrorhandling,
			{ "PolicyDecisionErrorHandling", "json.3gpp.suppfeat.policydecisionerrorhandling",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_37_ddneventpolicycontrol,
			{ "DDNEventPolicyControl", "json.3gpp.suppfeat.ddneventpolicycontrol",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_38_reallocationofcredit,
			{ "ReallocationOfCredit", "json.3gpp.suppfeat.reallocationofcredit",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_39_bdtpolicyrenegotiation,
			{ "BDTPolicyRenegotiation", "json.3gpp.suppfeat.bdtpolicyrenegotiation",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_40_extpolicydecisionerrorhandling,
			{ "ExtPolicyDecisionErrorHandling", "json.3gpp.suppfeat.extpolicydecisionerrorhandling",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_41_immediatetermination,
			{ "ImmediateTermination", "json.3gpp.suppfeat.immediatetermination",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_42_aggregateduelocchanges,
			{ "AggregatedUELocChanges", "json.3gpp.suppfeat.aggregateduelocchanges",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_43_es3xx,
			{ "ES3XX", "json.3gpp.suppfeat.es3xx",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_44_groupidlistchange,
			{ "GroupIdListChange", "json.3gpp.suppfeat.groupidlistchange",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_45_disableuenotification,
			{ "DisableUENotification", "json.3gpp.suppfeat.disableuenotification",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_46_offlinechonly,
			{ "OfflineChOnly", "json.3gpp.suppfeat.offlinechonly",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_47_dual_connectivity_redundant_up_paths,
			{ "Dual-Connectivity-redundant-UP-paths", "json.3gpp.suppfeat.dual_connectivity_redundant_up_paths",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_48_ddneventpolicycontrol2,
			{ "DDNEventPolicyControl2", "json.3gpp.suppfeat.ddneventpolicycontrol2",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_49_vplmn_qos_control,
			{ "VPLMN-QoS-Control", "json.3gpp.suppfeat.vplmn_qos_control",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_50_2g3giwk,
			{ "2G3GIWK", "json.3gpp.suppfeat.2g3giwk",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_51_timesensitivecommunication,
			{ "TimeSensitiveCommunication", "json.3gpp.suppfeat.timesensitivecommunication",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_52_enedge,
			{ "EnEDGE", "json.3gpp.suppfeat.enedge",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_53_satbackhaulcategorychg,
			{ "SatBackhaulCategoryChg", "json.3gpp.suppfeat.satbackhaulcategorychg",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_54_chfsetsupport,
			{ "CHFsetSupport", "json.3gpp.suppfeat.chfsetsupport",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_55_enatssss,
			{ "EnATSSS", "json.3gpp.suppfeat.enatssss",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_56_mpsfordts,
			{ "MPSforDTS", "json.3gpp.suppfeat.mpsfordts",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_57_routinginforemoval,
			{ "RoutingInfoRemoval", "json.3gpp.suppfeat.routinginforemoval",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_58_epra,
			{ "ePRA", "json.3gpp.suppfeat.epra",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_59_aminfluence,
			{ "AMInfluence", "json.3gpp.suppfeat.aminfluence",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_60_pvssupport,
			{ "PvsSupport", "json.3gpp.suppfeat.pvssupport",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_61_enena,
			{ "EneNA", "json.3gpp.suppfeat.enena",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_62_biumr,
			{ "BIUMR", "json.3gpp.suppfeat.biumr",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_63_easipreplacement,
			{ "EASIPreplacement", "json.3gpp.suppfeat.easipreplacement",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_64_exposuretoeas,
			{ "ExposureToEAS", "json.3gpp.suppfeat.exposuretoeas",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_65_simultconnectivity,
			{ "SimultConnectivity", "json.3gpp.suppfeat.simultconnectivity",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_66_sgwrest,
			{ "SGWRest", "json.3gpp.suppfeat.sgwrest",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_67_releasetoreactivate,
			{ "ReleaseToReactivate", "json.3gpp.suppfeat.releasetoreactivate",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_68_easdiscovery,
			{ "EASDiscovery", "json.3gpp.suppfeat.enena",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_69_accnetchargid_string,
			{ "AccNetChargId_String", "json.3gpp.suppfeat.accnetchargid_string",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},

	};

	static gint *ett[] = {
		&ett_json_base64decoded_eps_ie,
		&ett_json_base64decoded_nas5g_ie,
		&ett_json_3gpp_data,
	};

	/* Required function calls to register the header fields and subtrees used */
	proto_json_3gpp = proto_register_protocol("JSON 3GPP","JSON_3GPP", "json.3gpp");
	proto_register_field_array(proto_json_3gpp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Fill hash table with static headers */
	register_static_headers();
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
