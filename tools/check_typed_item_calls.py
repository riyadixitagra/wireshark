#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import re
import argparse
import signal
import subprocess

# This utility scans the dissector code for proto_tree_add_...() calls that constrain the type
# or length of the item added, and checks that the used item is acceptable.
#
# - Note that this can only work where the hf_item variable or length is passed in directly - simple
#   macro substitution is now done in a limited way 

# TODO:
# - Attempt to check for allowed encoding types (most likely will be literal values |'d)?
# - Create maps from type -> display types for hf items (see display (FIELDDISPLAY)) in docs/README.dissector


# Try to exit soon after Ctrl-C is pressed.
should_exit = False

def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)


warnings_found = 0
errors_found = 0

def name_has_one_of(name, substring_list):
    for word in substring_list:
        if name.lower().find(word) != -1:
            return True
    return False

# A call is an individual call to an API we are interested in.
# Internal to APICheck below.
class Call:
    def __init__(self, hf_name, macros, line_number=None, length=None, fields=None):
        self.hf_name = hf_name
        self.line_number = line_number
        self.fields = fields
        self.length = None
        if length:
            try:
                self.length = int(length)
            except:
                if length.isupper():
                    if length in macros:
                        try:
                            self.length = int(macros[length])
                        except:
                            pass
                pass


# These are variable names that have been seen to be used in calls..
common_hf_var_names = { 'hf_index', 'hf_item', 'hf_idx', 'hf_x', 'hf_id', 'hf_cookie', 'hf_flag',
                        'hf_dos_time', 'hf_dos_date', 'hf_value', 'hf_num',
                        'hf_cause_value', 'hf_uuid',
                        'hf_endian', 'hf_ip', 'hf_port', 'hf_suff', 'hf_string', 'hf_uint',
                        'hf_tag', 'hf_type', 'hf_hdr', 'hf_field', 'hf_opcode', 'hf_size',
                        'hf_entry', 'field' }

item_lengths = {}
item_lengths['FT_CHAR']  = 1
item_lengths['FT_UINT8']  = 1
item_lengths['FT_INT8']   = 1
item_lengths['FT_UINT16'] = 2
item_lengths['FT_INT16']  = 2
item_lengths['FT_UINT24'] = 3
item_lengths['FT_INT24']  = 3
item_lengths['FT_UINT32'] = 4
item_lengths['FT_INT32']  = 4
item_lengths['FT_UINT40'] = 5
item_lengths['FT_INT40']  = 5
item_lengths['FT_UINT48'] = 6
item_lengths['FT_INT48']  = 6
item_lengths['FT_UINT56'] = 7
item_lengths['FT_INT56']  = 7
item_lengths['FT_UINT64'] = 8
item_lengths['FT_INT64']  = 8
item_lengths['FT_ETHER']  = 6
# TODO: other types...


# A check for a particular API function.
class APICheck:
    def __init__(self, fun_name, allowed_types, positive_length=False):
        self.fun_name = fun_name
        self.allowed_types = allowed_types
        self.positive_length = positive_length
        self.calls = []

        if fun_name.startswith('ptvcursor'):
            # RE captures function name + 1st 2 args (always ptvc + hfindex)
            self.p = re.compile('[^\n]*' +  self.fun_name + '\s*\(([a-zA-Z0-9_]+),\s*([a-zA-Z0-9_]+)')
        elif fun_name.find('add_bitmask') == -1:
            # Normal case.
            # RE captures function name + 1st 2 args (always tree + hfindex + length)
            self.p = re.compile('[^\n]*' +  self.fun_name + '\s*\(([a-zA-Z0-9_]+),\s*([a-zA-Z0-9_]+),\s*[a-zA-Z0-9_]+,\s*[a-zA-Z0-9_]+,\s*([a-zA-Z0-9_]+)')
        else:
            # _add_bitmask functions.
            # RE captures function name + 1st + 4th args (always tree + hfindex)
            # 6th arg is 'fields'
            self.p = re.compile('[^\n]*' +  self.fun_name + '\s*\(([a-zA-Z0-9_]+),\s*[a-zA-Z0-9_]+,\s*[a-zA-Z0-9_]+,\s*([a-zA-Z0-9_]+)\s*,\s*[a-zA-Z0-9_]+\s*,\s*([a-zA-Z0-9_]+)\s*,')

        self.file = None
        self.mask_allowed = True
        if fun_name.find('proto_tree_add_bits_') != -1:
            self.mask_allowed = False


    def find_calls(self, file, macros):
        self.file = file
        self.calls = []

        with open(file, 'r') as f:
            contents = f.read()
            lines = contents.splitlines()
            total_lines = len(lines)
            for line_number,line in enumerate(lines):
                # Want to check this, and next few lines
                to_check = lines[line_number-1] + '\n'
                # Nothing to check if function name isn't in it
                if to_check.find(self.fun_name) != -1:
                    # Ok, add the next file lines before trying RE
                    for i in range(1, 4):
                        if to_check.find(';') != -1:
                            break
                        elif line_number+i < total_lines:
                            to_check += (lines[line_number-1+i] + '\n')
                    m = self.p.search(to_check)
                    if m:
                        fields = None
                        length = None

                        if self.fun_name.find('add_bitmask') != -1:
                            fields = m.group(3)
                        else:
                            if self.p.groups == 3:
                                length = m.group(3)

                        # Add call. We have length if re had 3 groups.
                        num_groups = self.p.groups
                        self.calls.append(Call(m.group(2),
                                               macros,
                                               line_number=line_number,
                                               length=length,
                                               fields=fields))



    def check_against_items(self, items_defined, items_declared, items_declared_extern, check_missing_items=False):
        global errors_found
        global warnings_found

        for call in self.calls:

            # Check lengths, but for now only for APIs that have length in bytes.
            if self.fun_name.find('add_bits') == -1 and call.hf_name in items_defined:
                if call.length and items_defined[call.hf_name].item_type in item_lengths:
                    if item_lengths[items_defined[call.hf_name].item_type] < call.length:
                        print('Warning:', self.file + ':' + str(call.line_number),
                              self.fun_name + ' called for', call.hf_name, ' - ',
                              'item type is', items_defined[call.hf_name].item_type, 'but call has len', call.length)
                        warnings_found += 1


            if self.positive_length and call.length != None:
                if call.length != -1 and call.length <= 0:
                    print('Error: ' +  self.fun_name + '(.., ' + call.hf_name + ', ...) called at ' +
                          self.file + ':' + str(call.line_number) +
                          ' with length ' + str(call.length) + ' - must be > 0 or -1')
                    # Inc global count of issues found.
                    errors_found += 1
            if call.hf_name in items_defined:
                if not items_defined[call.hf_name].item_type in self.allowed_types:
                    # Report this issue.
                    print('Error: ' +  self.fun_name + '(.., ' + call.hf_name + ', ...) called at ' +
                          self.file + ':' + str(call.line_number) +
                          ' with type ' + items_defined[call.hf_name].item_type)
                    print('    (allowed types are', self.allowed_types, ')\n')
                    # Inc global count of issues found.
                    errors_found += 1
                if not self.mask_allowed and items_defined[call.hf_name].mask_value != 0:
                    # Report this issue.
                    print('Error: ' +  self.fun_name + '(.., ' + call.hf_name + ', ...) called at ' +
                          self.file + ':' + str(call.line_number) +
                          ' with mask ' + items_defined[call.hf_name].mask + '    (must be zero!)\n')
                    # Inc global count of issues found.
                    errors_found += 1


            elif check_missing_items:
                if call.hf_name in items_declared and not call.hf_name in items_declared_extern:
                #not in common_hf_var_names:
                    print('Warning:', self.file + ':' + str(call.line_number),
                          self.fun_name + ' called for "' + call.hf_name + '"', ' - but no item found')
                    warnings_found += 1



class ProtoTreeAddItemCheck(APICheck):
    def __init__(self, ptv=None):

        # RE will capture whole call.

        if not ptv:
            # proto_item *
            # proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
            #                     const gint start, gint length, const guint encoding)
            self.fun_name = 'proto_tree_add_item'
            self.p = re.compile('[^\n]*' + self.fun_name + '\s*\(\s*[a-zA-Z0-9_]+?,\s*([a-zA-Z0-9_]+?),\s*[a-zA-Z0-9_\+\s]+?,\s*[^,.]+?,\s*(.+),\s*([^,.]+?)\);')
        else:
            # proto_item *
            # ptvcursor_add(ptvcursor_t *ptvc, int hfindex, gint length,
            #               const guint encoding)
            self.fun_name = 'ptvcursor_add'
            self.p = re.compile('[^\n]*' + self.fun_name + '\s*\([^,.]+?,\s*([^,.]+?),\s*([^,.]+?),\s*([a-zA-Z0-9_\-\>]+)')


    def find_calls(self, file, macros):
        self.file = file
        self.calls = []
        with open(file, 'r') as f:

            contents = f.read()
            lines = contents.splitlines()
            total_lines = len(lines)
            for line_number,line in enumerate(lines):
                # Want to check this, and next few lines
                to_check = lines[line_number-1] + '\n'
                # Nothing to check if function name isn't in it
                fun_idx = to_check.find(self.fun_name)
                if fun_idx != -1:
                    # Ok, add the next file lines before trying RE
                    for i in range(1, 5):
                        if to_check.find(';') != -1:
                            break
                        elif line_number+i < total_lines:
                            to_check += (lines[line_number-1+i] + '\n')
                    # Lose anything before function call itself.
                    to_check = to_check[fun_idx:]
                    m = self.p.search(to_check)
                    if m:
                        # Throw out if parens not matched
                        if m.group(0).count('(') != m.group(0).count(')'):
                            continue

                        enc = m.group(3)
                        hf_name = m.group(1)
                        if not enc.startswith('ENC_'):
                            if not enc in { 'encoding', 'enc', 'client_is_le', 'cigi_byte_order', 'endian', 'endianess', 'machine_encoding', 'byte_order', 'bLittleEndian',
                                            'p_mq_parm->mq_str_enc', 'p_mq_parm->mq_int_enc',
                                            'iEnc', 'strid_enc', 'iCod', 'nl_data->encoding',
                                            'argp->info->encoding', 'gquic_info->encoding', 'writer_encoding',
                                            'tds_get_int2_encoding(tds_info)',
                                            'tds_get_int4_encoding(tds_info)',
                                            'tds_get_char_encoding(tds_info)',
                                            'info->encoding',
                                            'item->encoding',
                                            'DREP_ENC_INTEGER(drep)', 'string_encoding', 'item', 'type',
                                            'dvb_enc_to_item_enc(encoding)',
                                            'packet->enc',
                                            'IS_EBCDIC(uCCS) ? ENC_EBCDIC : ENC_ASCII',
                                            'DREP_ENC_INTEGER(hdr->drep)',
                                            'dhcp_uuid_endian',
                                            'payload_le',
                                            'local_encoding',
                                            'big_endian',
                                            'hf_data_encoding',
                                            'IS_EBCDIC(eStr) ? ENC_EBCDIC : ENC_ASCII',
                                            'big_endian ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN',
                                            '(skip == 1) ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN',
                                            'pdu_info->sbc', 'pdu_info->mbc',
                                            'seq_info->txt_enc | ENC_NA',
                                            'BASE_SHOW_UTF_8_PRINTABLE'
                                          }:
                                global warnings_found

                                print('Warning:', self.file + ':' + str(line_number),
                                      self.fun_name + ' called for "' + hf_name + '"',  'check last/enc param:', enc, '?')
                                warnings_found += 1
                        self.calls.append(Call(hf_name, macros, line_number=line_number, length=m.group(2)))

    def check_against_items(self, items_defined, items_declared, items_declared_extern, check_missing_items=False):
        # For now, only complaining if length if call is longer than the item type implies.
        #
        # Could also be bugs where the length is always less than the type allows.
        # Would involve keeping track (in the item) of whether any call had used the full length.

        global warnings_found

        for call in self.calls:
            if call.hf_name in items_defined:
                if call.length and items_defined[call.hf_name].item_type in item_lengths:
                    if item_lengths[items_defined[call.hf_name].item_type] < call.length:
                        print('Warning:', self.file + ':' + str(call.line_number),
                              self.fun_name + ' called for', call.hf_name, ' - ',
                              'item type is', items_defined[call.hf_name].item_type, 'but call has len', call.length)
                        warnings_found += 1
            elif check_missing_items:
                if call.hf_name in items_declared and not call.hf_name in items_declared_extern:
                #not in common_hf_var_names:
                    print('Warning:', self.file + ':' + str(call.line_number),
                          self.fun_name + ' called for "' + call.hf_name + '"', ' - but no item found')
                    warnings_found += 1



##################################################################################################
# This is a set of items (by filter name) where we know that the bitmask is non-contiguous,
# but is still believed to be correct.
known_non_contiguous_fields = { 'wlan.fixed.capabilities.cfpoll.sta',
                                'wlan.wfa.ie.wme.qos_info.sta.reserved',
                                'btrfcomm.frame_type',   # https://os.itec.kit.edu/downloads/sa_2006_roehricht-martin_flow-control-in-bluez.pdf
                                'capwap.control.message_element.ac_descriptor.dtls_policy.r', # RFC 5415
                                'couchbase.extras.subdoc.flags.reserved',
                                'wlan.fixed.capabilities.cfpoll.ap',   # These are 3 separate bits...
                                'wlan.wfa.ie.wme.tspec.ts_info.reserved', # matches other fields in same sequence
                                'zbee_zcl_se.pp.attr.payment_control_configuration.reserved', # matches other fields in same sequence
                                'zbee_zcl_se.pp.snapshot_payload_cause.reserved',  # matches other fields in same sequence
                                'ebhscr.eth.rsv',  # matches other fields in same sequence
                                'v120.lli',  # non-contiguous field (http://www.acacia-net.com/wwwcla/protocol/v120_l2.htm)
                                'stun.type.class',
                                'bssgp.csg_id', 'tiff.t6.unused', 'artnet.ip_prog_reply.unused',
                                'telnet.auth.mod.enc', 'osc.message.midi.bender', 'btle.data_header.rfu',
                                'stun.type.method', # figure 3 in rfc 5389
                                'tds.done.status', # covers all bits in bitset
                                'hf_iax2_video_csub',  # RFC 5456, table 8.7
                                'iax2.video.subclass',
                                'dnp3.al.ana.int',
                                'pwcesopsn.cw.lm',
                                'gsm_a.rr.format_id', # EN 301 503
                                'siii.mst.phase', # comment in code seems convinced
                                'xmcp.type.class',
                                'xmcp.type.method'
                              }
##################################################################################################


field_widths = {
    'FT_BOOLEAN' : 64,   # TODO: Width depends upon 'display' field
    'FT_CHAR'    : 8,
    'FT_UINT8'   : 8,
    'FT_INT8'    : 8,
    'FT_UINT16'  : 16,
    'FT_INT16'   : 16,
    'FT_UINT24'  : 24,
    'FT_INT24'   : 24,
    'FT_UINT32'  : 32,
    'FT_INT32'   : 32,
    'FT_UINT40'  : 40,
    'FT_INT40'   : 40,
    'FT_UINT48'  : 48,
    'FT_INT48'   : 48,
    'FT_UINT56'  : 56,
    'FT_INT56'   : 56,
    'FT_UINT64'  : 64,
    'FT_INT64'   : 64
}

def is_ignored_consecutive_filter(filter):
    ignore_patterns = [
        re.compile(r'^elf.sh_type'),
        re.compile(r'^elf.p_type'),
        re.compile(r'^btavrcp.pdu_id'),
        re.compile(r'^nstrace.trcdbg.val(\d+)'),
        re.compile(r'^netlogon.dummy_string'),
        re.compile(r'^opa.reserved'),
        re.compile(r'^mpls_pm.timestamp\d\..*'),
        re.compile(r'^wassp.data.mu_mac'),
        re.compile(r'^thrift.type'),
        re.compile(r'^quake2.game.client.command.move.angles'),
        re.compile(r'^ipp.enum_value'),
        re.compile(r'^idrp.error.subcode'),
        re.compile(r'^ftdi-ft.lValue'),
        re.compile(r'^6lowpan.src'),
        re.compile(r'^couchbase.flex_frame.frame.id'),
        re.compile(r'^rtps.param.id'),
        re.compile(r'^rtps.locator.port'),
        re.compile(r'^sigcomp.udvm.value'),
        re.compile(r'^opa.mad.attributemodifier.n'),
        re.compile(r'^smb.cmd'),
        re.compile(r'^sctp.checksum'),
        re.compile(r'^dhcp.option.end'),
        re.compile(r'^nfapi.num.bf.vector.bf.value'),
        re.compile(r'^dnp3.al.range.abs'),
        re.compile(r'^dnp3.al.range.quantity'),
        re.compile(r'^dnp3.al.index'),
        re.compile(r'^dnp3.al.size'),
        re.compile(r'^ftdi-ft.hValue'),
        re.compile(r'^homeplug_av.op_attr_cnf.data.sw_sub'),
        re.compile(r'^radiotap.he_mu.preamble_puncturing'),
        re.compile(r'^ndmp.file'),
        re.compile(r'^ocfs2.dlm.lvb'),
        re.compile(r'^oran_fh_cus.reserved'),
        re.compile(r'^qnet6.kif.msgsend.msg.read.xtypes0-7'),
        re.compile(r'^qnet6.kif.msgsend.msg.write.xtypes0-7'),
        re.compile(r'^mih.sig_strength'),
        re.compile(r'^couchbase.flex_frame.frame.len'),
        re.compile(r'^nvme-rdma.read_to_host_req'),
        re.compile(r'^rpcap.dummy'),
        re.compile(r'^sflow.flow_sample.output_interface'),
        re.compile(r'^socks.results'),
        re.compile(r'^opa.mad.attributemodifier.p'),
        re.compile(r'^v5ua.efa'),
        re.compile(r'^zbncp.data.tx_power'),
        re.compile(r'^zbncp.data.nwk_addr'),
        re.compile(r'^zbee_zcl_hvac.pump_config_control.attr.ctrl_mode'),
        re.compile(r'^nat-pmp.external_port'),
        re.compile(r'^zbee_zcl.attr.float'),
        re.compile(r'^wpan-tap.phr.fsk_ms.mode'),
        re.compile(r'^mysql.exec_flags'),
        re.compile(r'^pim.metric_pref'),
        re.compile(r'^modbus.regval_float'),
        re.compile(r'^alcap.cau.value'),
        re.compile(r'^bpv7.crc_field'),
        re.compile(r'^at.chld.mode'),
        re.compile(r'^btl2cap.psm'),
        re.compile(r'^srvloc.srvtypereq.nameauthlistlen'),
        re.compile(r'^a11.ext.code'),
        re.compile(r'^adwin_config.port'),
        re.compile(r'^afp.unknown'),
        re.compile(r'^ansi_a_bsmap.mid.digit_1'),
        re.compile(r'^ber.unknown.OCTETSTRING'),
        re.compile(r'^btatt.handle'),
        re.compile(r'^btl2cap.option_flushto'),
        re.compile(r'^cip.network_segment.prod_inhibit'),
        re.compile(r'^cql.result.rows.table_name'),
        re.compile(r'^dcom.sa.vartype'),
        re.compile(r'^f5ethtrailer.slot'),
        re.compile(r'^ipdr.cm_ipv6_addr'),
        re.compile(r'^mojito.kuid'),
        re.compile(r'^mtp3.priority'),
        re.compile(r'^pw.cw.length'),
        re.compile(r'^rlc.ciphered_data'),
        re.compile(r'^vp8.pld.pictureid'),
        re.compile(r'^gryphon.sched.channel'),
        re.compile(r'^pn_io.ioxs'),
        re.compile(r'^pn_dcp.block_qualifier_reset'),
        re.compile(r'^pn_dcp.suboption_device_instance'),
        re.compile(r'^nfs.attr'),
        re.compile(r'^nfs.create_session_flags'),
        re.compile(r'^rmt-lct.toi64'),
        re.compile(r'^gryphon.data.header_length'),
        re.compile(r'^quake2.game.client.command.move.movement'),
        re.compile(r'^isup.parameter_type'),
        re.compile(r'^cip.port'),
        re.compile(r'^adwin.fifo_no'),
        re.compile(r'^bthci_evt.hci_vers_nr'),
        re.compile(r'^gryphon.usdt.stmin_active'),
        re.compile(r'^dnp3.al.anaout.int'),
        re.compile(r'^dnp3.al.ana.int'),
        re.compile(r'^dnp3.al.cnt'),
        re.compile(r'^bthfp.chld.mode'),
        re.compile(r'^nat-pmp.pml'),
        re.compile(r'^isystemactivator.actproperties.ts.hdr'),
        re.compile(r'^rtpdump.txt_addr'),
        re.compile(r'^unistim.vocoder.id'),
        re.compile(r'^mac.ueid')
    ]

    for patt in ignore_patterns:
        if patt.match(filter):
            return True
    return False



# The relevant parts of an hf item.  Used as value in dict where hf variable name is key.
class Item:

    previousItem = None

    def __init__(self, filename, hf, filter, label, item_type, type_modifier, macros, mask=None,
                 check_mask=False, mask_exact_width=False, check_label=False, check_consecutive=False):
        self.filename = filename
        self.hf = hf
        self.filter = filter
        self.label = label

        self.mask = mask
        self.mask_exact_width = mask_exact_width

        global warnings_found

        self.set_mask_value(macros)

        if check_consecutive:
            if Item.previousItem and Item.previousItem.filter == filter:
                if label != Item.previousItem.label:
                    if not is_ignored_consecutive_filter(self.filter):
                        print('Warning:', filename, hf, ': - filter "' + filter +
                            '" appears consecutively - labels are "' + Item.previousItem.label + '" and "' + label + '"')
                        warnings_found += 1

            Item.previousItem = self


        # Optionally check label.
        if check_label:
            if label.startswith(' ') or label.endswith(' '):
                print('Warning: ' + filename, hf, 'filter "' + filter +  '" label' + label + '" begins or ends with a space')
                warnings_found += 1

            if (label.count('(') != label.count(')') or
                label.count('[') != label.count(']') or
                label.count('{') != label.count('}')):
                # Ignore if includes quotes, as may be unbalanced.
                if label.find("'") == -1:
                    print('Warning: ' + filename, hf, 'filter "' + filter + '" label', '"' + label + '"', 'has unbalanced parens/braces/brackets')
                    warnings_found += 1
            if item_type != 'FT_NONE' and label.endswith(':'):
                print('Warning: ' + filename, hf, 'filter "' + filter + '" label', '"' + label + '"', 'ends with an unnecessary colon')
                warnings_found += 1

        self.item_type = item_type
        self.type_modifier = type_modifier

        # Optionally check that mask bits are contiguous
        if check_mask:
            if self.mask_read and not mask in { 'NULL', '0x0', '0', '0x00'}:
                self.check_contiguous_bits(mask)
                self.check_num_digits(self.mask)
                self.check_digits_all_zeros(self.mask)


    def __str__(self):
        return 'Item ({0} "{1}" {2} type={3}:{4} mask={5})'.format(self.filename, self.label, self.filter, self.item_type, self.type_modifier, self.mask)



    def set_mask_value(self, macros):
        try:
            self.mask_read = True

            # Substitute mask if found as a macro..
            if self.mask in macros:
                self.mask = macros[self.mask]
            elif any(not c in '0123456789abcdefABCDEFxX' for c in self.mask):
                self.mask_read = False
                self.mask_value = 0
                return


            # Read according to the appropriate base.
            if self.mask.startswith('0x'):
                self.mask_value = int(self.mask, 16)
            elif self.mask.startswith('0'):
                self.mask_value = int(self.mask, 8)
            else:
                self.mask_value = int(self.mask, 10)
        except:
            self.mask_read = False
            self.mask_value = 0


    # Return true if bit position n is set in value.
    def check_bit(self, value, n):
        return (value & (0x1 << n)) != 0

    # Output a warning if non-contigous bits are found in the mask (guint64).
    # Note that this legimately happens in several dissectors where multiple reserved/unassigned
    # bits are conflated into one field.
    # TODO: there is probably a cool/efficient way to check this?
    def check_contiguous_bits(self, mask):
        if not self.mask_value:
            return

        # Do see non-contiguous bits often for these..
        if name_has_one_of(self.hf, ['reserved', 'unknown', 'unused', 'spare']):
            return
        if name_has_one_of(self.label, ['reserved', 'unknown', 'unused', 'spare']):
            return


        # Walk past any l.s. 0 bits
        n = 0
        while not self.check_bit(self.mask_value, n) and n <= 63:
            n += 1
        if n==63:
            return

        mask_start = n
        # Walk through any bits that are set
        while self.check_bit(self.mask_value, n) and n <= 63:
            n += 1
        n += 1

        if n >= 63:
            return

        # Look up the field width
        field_width = 0
        if not self.item_type in field_widths:
            print('unexpected item_type is ', self.item_type)
            field_width = 64
        else:
            field_width = self.get_field_width_in_bits()


        # Its a problem is the mask_width is > field_width - some of the bits won't get looked at!?
        mask_width = n-1-mask_start
        if field_width is not None and (mask_width > field_width):
            # N.B. No call, so no line number.
            print(self.filename + ':', self.hf, 'filter=', self.filter, self.item_type, 'so field_width=', field_width,
                  'but mask is', mask, 'which is', mask_width, 'bits wide!')
            global warnings_found
            warnings_found += 1

        # Now, any more zero set bits are an error!
        if self.filter in known_non_contiguous_fields or self.filter.startswith('rtpmidi'):
            # Don't report if we know this one is Ok.
            return
        while n <= 63:
            if self.check_bit(self.mask_value, n):
                print('Warning:', self.filename, self.hf, 'filter=', self.filter, ' - mask with non-contiguous bits',
                      mask, '(', hex(self.mask_value), ')')
                warnings_found += 1
                return
            n += 1

    def get_field_width_in_bits(self):
        if self.item_type == 'FT_BOOLEAN':
            if self.type_modifier == 'NULL':
                return 8  # i.e. 1 byte
            elif self.type_modifier == 'BASE_NONE':
                return 8
            elif self.type_modifier == 'SEP_DOT':   # from proto.h, only meant for FT_BYTES
                return 64
            else:
                try:
                    # For FT_BOOLEAN, modifier is just numerical number of bits. Round up to next nibble.
                    return int((int(self.type_modifier) + 3)/4)*4
                except:
                    return None
        else:
            if self.item_type in field_widths:
                # Lookup fixed width for this type
                return field_widths[self.item_type]
            else:
                return None

    def check_num_digits(self, mask):
        if mask.startswith('0x') and len(mask) > 3:
            global warnings_found
            global errors_found
            # Warn if odd number of digits/  TODO: only if >= 5?
            if len(mask) % 2  and self.item_type != 'FT_BOOLEAN':
                print('Warning:', self.filename, self.hf, 'filter=', self.filter, ' - mask has odd number of digits', mask,
                      'expected max for', self.item_type, 'is', int((self.get_field_width_in_bits())/4))
                warnings_found += 1

            if self.item_type in field_widths:
                # Longer than it should be?
                width_in_bits = self.get_field_width_in_bits()
                if width_in_bits is None:
                    return
                if len(mask)-2 > width_in_bits/4:
                    extra_digits = mask[2:2+(len(mask)-2 - int(self.get_field_width_in_bits()/4))]
                    # Its definitely an error if any of these are non-zero, as they won't have any effect!
                    if extra_digits != '0'*len(extra_digits):
                        print('Error:', self.filename, self.hf, 'filter=', self.filter, 'mask', self.mask, "with len is", len(mask)-2,
                              "but type", self.item_type, " indicates max of", int(self.get_field_width_in_bits()/4),
                              "and extra digits are non-zero (" + extra_digits + ")")
                        errors_found += 1
                    else:
                        # Has extra leading zeros, still confusing, so warn.
                        print('Warning:', self.filename, self.hf, 'filter=', self.filter, 'mask', self.mask, "with len", len(mask)-2,
                              "but type", self.item_type, " indicates max of", int(self.get_field_width_in_bits()/4))
                        warnings_found += 1

                # Strict/fussy check - expecting mask length to match field width exactly!
                # Currently only doing for FT_BOOLEAN, and don't expect to be in full for 64-bit fields!
                if self.mask_exact_width:
                    ideal_mask_width = int(self.get_field_width_in_bits()/4)
                    if self.item_type == 'FT_BOOLEAN' and ideal_mask_width < 16 and len(mask)-2 != ideal_mask_width:
                        print('Warning:', self.filename, self.hf, 'filter=', self.filter, 'mask', self.mask, "with len", len(mask)-2,
                                "but type", self.item_type, "|", self.type_modifier,  " indicates should be", int(self.get_field_width_in_bits()/4))
                        warnings_found += 1

            else:
                # This type shouldn't have a mask set at all.
                print('Warning:', self.filename, self.hf, 'filter=', self.filter, ' - item has type', self.item_type, 'but mask set:', mask)
                warnings_found += 1

    def check_digits_all_zeros(self, mask):
        if mask.startswith('0x') and len(mask) > 3:
            if mask[2:] == '0'*(len(mask)-2):
                print('Warning:', self.filename, self.hf, 'filter=', self.filter, ' - item mask has all zeros - this is confusing! :', '"' + mask + '"')
                global warnings_found
                warnings_found += 1

    # Return True if appears to be a match
    def check_label_vs_filter(self, reportError=True):
        global warnings_found

        last_filter = self.filter.split('.')[-1]
        last_filter_orig = last_filter
        last_filter = last_filter.replace('-', '')
        last_filter = last_filter.replace('_', '')
        last_filter = last_filter.replace(' ', '')
        label = self.label
        label_orig = label
        label = label.replace(' ', '')
        label = label.replace('-', '')
        label = label.replace('_', '')
        label = label.replace('(', '')
        label = label.replace(')', '')
        label = label.replace('/', '')


        # OK if filter is abbrev of label.
        label_words = self.label.split(' ')
        label_words = [w for w in label_words if len(w)]
        if len(label_words) == len(last_filter):
            #print(label_words)
            abbrev_letters = [w[0] for w in label_words]
            abbrev = ''.join(abbrev_letters)
            if abbrev.lower() == last_filter.lower():
                return True

        # If both have numbers, they should probably match!
        label_numbers =  re.findall(r'\d+', label_orig)
        filter_numbers = re.findall(r'\d+', last_filter_orig)
        if len(label_numbers) == len(filter_numbers) and label_numbers != filter_numbers:
            if reportError:
                print('Warning:', self.filename, self.hf, 'label="' + self.label + '" has different **numbers** from  filter="' + self.filter + '"')
                print(label_numbers, filter_numbers)
                warnings_found += 1
            return False

        # If they match after trimming number from filter, they should match.
        if label.lower() == last_filter.lower().rstrip("0123456789"):
            return True

        # Are they just different?
        if label.lower().find(last_filter.lower()) == -1:
            if reportError:
                print('Warning:', self.filename, self.hf, 'label="' + self.label + '" does not seem to match filter="' + self.filter + '"')
                warnings_found += 1
            return False

        return True


class CombinedCallsCheck:
    def __init__(self, file, apiChecks):
        self.file = file
        self.apiChecks = apiChecks
        self.get_all_calls()

    def get_all_calls(self):
        self.all_calls = []
        # Combine calls into one list.
        for check in self.apiChecks:
            self.all_calls += check.calls

        # Sort by line number.
        self.all_calls.sort(key=lambda x:x.line_number)

    def check_consecutive_item_calls(self):
        lines = open(self.file, 'r').read().splitlines()

        prev = None
        for call in self.all_calls:

            # These names commonly do appear together..
            if name_has_one_of(call.hf_name, [ 'unused', 'unknown', 'spare', 'reserved', 'default']):
                return

            if prev and call.hf_name == prev.hf_name:
                # More compelling if close together..
                if call.line_number>prev.line_number and call.line_number-prev.line_number <= 4:
                    scope_different = False
                    for l in range(prev.line_number, call.line_number-1):
                        if lines[l].find('{') != -1 or lines[l].find('}') != -1 or lines[l].find('else') != -1 or lines[l].find('break;') != -1 or lines[l].find('if ') != -1:
                            scope_different = True
                            break
                    # Also more compelling if check for and scope changes { } in lines in-between?
                    if not scope_different:
                        print('Warning:', f + ':' + str(call.line_number),
                              call.hf_name + ' called consecutively at line', call.line_number, '- previous at', prev.line_number)
                        global warnings_found
                        warnings_found += 1
            prev = call




# These are APIs in proto.c that check a set of types at runtime and can print '.. is not of type ..' to the console
# if the type is not suitable.
apiChecks = []
apiChecks.append(APICheck('proto_tree_add_item_ret_uint', { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_uint', { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}, positive_length=True))
apiChecks.append(APICheck('ptvcursor_add_ret_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}, positive_length=True))
apiChecks.append(APICheck('ptvcursor_add_ret_string', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('ptvcursor_add_ret_boolean', { 'FT_BOOLEAN'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_uint64', { 'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_int64', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_boolean', { 'FT_BOOLEAN'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_string_and_length', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_display_string_and_length', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING',
                                                                                 'FT_STRINGZPAD', 'FT_STRINGZTRUNC', 'FT_BYTES', 'FT_UINT_BYTES'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_time_string', { 'FT_ABSOLUTE_TIME', 'FT_RELATIVE_TIME'}))
apiChecks.append(APICheck('proto_tree_add_uint', {  'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_uint_format_value', {  'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_uint_format', {  'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_uint64', { 'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_int64', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))
apiChecks.append(APICheck('proto_tree_add_int64_format_value', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))
apiChecks.append(APICheck('proto_tree_add_int64_format', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))
apiChecks.append(APICheck('proto_tree_add_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('proto_tree_add_int_format_value', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('proto_tree_add_int_format', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('proto_tree_add_boolean', { 'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_boolean64', { 'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_float', { 'FT_FLOAT'}))
apiChecks.append(APICheck('proto_tree_add_float_format', { 'FT_FLOAT'}))
apiChecks.append(APICheck('proto_tree_add_float_format_value', { 'FT_FLOAT'}))
apiChecks.append(APICheck('proto_tree_add_double', { 'FT_DOUBLE'}))
apiChecks.append(APICheck('proto_tree_add_double_format', { 'FT_DOUBLE'}))
apiChecks.append(APICheck('proto_tree_add_double_format_value', { 'FT_DOUBLE'}))
apiChecks.append(APICheck('proto_tree_add_string', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_string_format', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_string_format_value', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_guid', { 'FT_GUID'}))
apiChecks.append(APICheck('proto_tree_add_oid', { 'FT_OID'}))
apiChecks.append(APICheck('proto_tree_add_none_format', { 'FT_NONE'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_varint', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32', 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64',
                                                              'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM',
                                                              'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64',}))
apiChecks.append(APICheck('proto_tree_add_boolean_bits_format_value', { 'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_boolean_bits_format_value64', { 'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_ascii_7bits_item', { 'FT_STRING'}))
# TODO: positions are different, and takes 2 hf_fields..
#apiChecks.append(APICheck('proto_tree_add_checksum', { 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}))
apiChecks.append(APICheck('proto_tree_add_int64_bits_format_value', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))

# TODO: add proto_tree_add_bytes_item, proto_tree_add_time_item ?

bitmask_types = { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32',
                  'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32',
                  'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64',
                  'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64',
                   'FT_BOOLEAN'}
apiChecks.append(APICheck('proto_tree_add_bitmask', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_tree', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_ret_uint64', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_with_flags', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_with_flags_ret_uint64', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_value', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_value_with_flags', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_len', bitmask_types))

add_bits_types = { 'FT_CHAR', 'FT_BOOLEAN',
                   'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64',
                   'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32', 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64',
                    'FT_BYTES'}
apiChecks.append(APICheck('proto_tree_add_bits_item',    add_bits_types))
apiChecks.append(APICheck('proto_tree_add_bits_ret_val', add_bits_types))

# TODO: doesn't even have an hf_item !
#apiChecks.append(APICheck('proto_tree_add_bitmask_text', bitmask_types))

# Check some ptvcuror calls too.
apiChecks.append(APICheck('ptvcursor_add_ret_uint', { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_boolean', { 'FT_BOOLEAN'}))


# Also try to check proto_tree_add_item() calls (for length)
apiChecks.append(ProtoTreeAddItemCheck())
apiChecks.append(ProtoTreeAddItemCheck(True)) # for ptvcursor_add()



def removeComments(code_string):
    code_string = re.sub(re.compile(r"/\*.*?\*/",re.DOTALL ) ,"" , code_string) # C-style comment
    code_string = re.sub(re.compile(r"//.*?\n" ) ,"" , code_string)             # C++-style comment
    code_string = re.sub(re.compile(r"#if 0.*?#endif",re.DOTALL ) ,"" , code_string) # Ignored region

    return code_string

# Test for whether the given file was automatically generated.
def isGeneratedFile(filename):
    # Open file
    f_read = open(os.path.join(filename), 'r')
    lines_tested = 0
    for line in f_read:
        # The comment to say that its generated is near the top, so give up once
        # get a few lines down.
        if lines_tested > 10:
            f_read.close()
            return False
        if (line.find('Generated automatically') != -1 or
            line.find('Generated Automatically') != -1 or
            line.find('Autogenerated from') != -1 or
            line.find('is autogenerated') != -1 or
            line.find('automatically generated by Pidl') != -1 or
            line.find('Created by: The Qt Meta Object Compiler') != -1 or
            line.find('This file was generated') != -1 or
            line.find('This filter was automatically generated') != -1 or
            line.find('This file is auto generated, do not edit!') != -1):

            f_read.close()
            return True
        lines_tested = lines_tested + 1

    # OK, looks like a hand-written file!
    f_read.close()
    return False


def find_macros(filename):
    macros = {}
    with open(filename, 'r') as f:
        contents = f.read()
        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        matches = re.finditer( r'#define\s*([A-Z0-9_]*)\s*([0-9xa-fA-F]*)\n', contents)
        for m in matches:
            # Store this mapping.
            macros[m.group(1)] = m.group(2)
    return macros


# Look for hf items (i.e. full item to be registered) in a dissector file.
def find_items(filename, macros, check_mask=False, mask_exact_width=False, check_label=False, check_consecutive=False):
    is_generated = isGeneratedFile(filename)
    items = {}
    with open(filename, 'r') as f:
        contents = f.read()
        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        # N.B. re extends all the way to HFILL to avoid greedy matching
        matches = re.finditer( r'.*\{\s*\&(hf_[a-z_A-Z0-9]*)\s*,\s*{\s*\"(.*?)\"\s*,\s*\"(.*?)\"\s*,\s*(.*?)\s*,\s*([0-9A-Z_\|\s]*?)\s*,\s*(.*?)\s*,\s*(.*?)\s*,\s*([a-zA-Z0-9\W\s_\u00f6\u00e4]*?)\s*,\s*HFILL', contents)
        for m in matches:
            # Store this item.
            hf = m.group(1)
            items[hf] = Item(filename, hf, filter=m.group(3), label=m.group(2), item_type=m.group(4),
                             type_modifier=m.group(5),
                             macros=macros,
                             mask=m.group(7),
                             check_mask=check_mask,
                             mask_exact_width=mask_exact_width,
                             check_label=check_label,
                             check_consecutive=(not is_generated and check_consecutive))
    return items


# Looking for args to ..add_bitmask_..() calls that are not NULL-terminated or  have repeated items.
# TODO: some dissectors have similar-looking hf arrays for other reasons, so need to cross-reference with
# the 6th arg of ..add_bitmask_..() calls...
# TODO: return items (rather than local checks) from here so can be checked against list of calls for given filename
def find_field_arrays(filename, all_fields, all_hf):
    global warnings_found
    with open(filename, 'r') as f:
        contents = f.read()
        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        # Find definition of hf array
        matches = re.finditer(r'static\s*g?int\s*\*\s*const\s+([a-zA-Z0-9_]*)\s*\[\]\s*\=\s*\{([a-zA-Z0-9,_\&\s]*)\}', contents)
        for m in matches:
            name = m.group(1)
            # Ignore if not used in a call to an _add_bitmask_ API
            if name not in all_fields:
                continue
            all_fields = m.group(2)
            all_fields = all_fields.replace('&', '')
            all_fields = all_fields.replace(',', '')

            # Get list of each hf field in the array
            fields = all_fields.split()

            if fields[0].startswith('ett_'):
                continue
            if fields[-1].find('NULL') == -1 and fields[-1] != '0':
                print('Warning:', filename, name, 'is not NULL-terminated - {', ', '.join(fields), '}')
                warnings_found += 1

            # Do any hf items reappear?
            seen_fields = set()
            for f in fields:
                if f in seen_fields:
                    print(filename, name, f, 'already added!')
                    warnings_found += 1
                seen_fields.add(f)

            # Check for duplicated flags among entries..
            combined_mask = 0x0
            for f in fields[0:-1]:
                if f in all_hf:
                    new_mask = all_hf[f].mask_value
                    if new_mask & combined_mask:
                        print('Warning:', filename, name, 'has overlapping mask - {', ', '.join(fields), '} combined currently', hex(combined_mask), f, 'adds', hex(new_mask))
                        warnings_found += 1
                    combined_mask |= new_mask

            # Make sure all entries have the same width
            set_field_width = None
            for f in fields[0:-1]:
                if f in all_hf:
                    new_field_width = all_hf[f].get_field_width_in_bits()
                    if set_field_width is not None and new_field_width != set_field_width:
                        print('Warning:', filename, name, 'set items not all same width - {', ', '.join(fields), '} seen', set_field_width, 'now', new_field_width)
                        warnings_found += 1
                    set_field_width = new_field_width

    return []

def find_item_declarations(filename):
    items = set()

    with open(filename, 'r') as f:
        lines = f.read().splitlines()
        p = re.compile(r'^static int (hf_[a-zA-Z0-9_]*)\s*\=\s*-1;')
        for line in lines:
            m = p.search(line)
            if m:
                items.add(m.group(1))
    return items

def find_item_extern_declarations(filename):
    items = set()
    with open(filename, 'r') as f:
        lines = f.read().splitlines()
        p = re.compile(r'^\s*(hf_[a-zA-Z0-9_]*)\s*\=\s*proto_registrar_get_id_byname\s*\(')
        for line in lines:
            m = p.search(line)
            if m:
                items.add(m.group(1))
    return items


def is_dissector_file(filename):
    p = re.compile(r'.*(packet|file)-.*\.c$')
    return p.match(filename)


def findDissectorFilesInFolder(folder, recursive=False):
    dissector_files = []

    if recursive:
        for root, subfolders, files in os.walk(folder):
            for f in files:
                if should_exit:
                    return
                f = os.path.join(root, f)
                dissector_files.append(f)
    else:
        for f in sorted(os.listdir(folder)):
            if should_exit:
                return
            filename = os.path.join(folder, f)
            dissector_files.append(filename)

    return [x for x in filter(is_dissector_file, dissector_files)]



# Run checks on the given dissector file.
def checkFile(filename, check_mask=False, mask_exact_width=False, check_label=False, check_consecutive=False,
              check_missing_items=False, check_bitmask_fields=False, label_vs_filter=False):
    # Check file exists - e.g. may have been deleted in a recent commit.
    if not os.path.exists(filename):
        print(filename, 'does not exist!')
        return

    # Find simple macros so can subtitute into items and calls.
    macros = find_macros(filename)

    # Find important parts of items.
    items_defined = find_items(filename, macros, check_mask, mask_exact_width, check_label, check_consecutive)
    items_extern_declared = {}

    items_declared = {}
    if check_missing_items:
        items_declared = find_item_declarations(filename)
        items_extern_declared = find_item_extern_declarations(filename)

    fields = set()

    # Check each API
    for c in apiChecks:
        c.find_calls(filename, macros)
        for call in c.calls:
            if call.fields:
                fields.add(call.fields)

        c.check_against_items(items_defined, items_declared, items_extern_declared, check_missing_items)

    # Checking for lists of fields for add_bitmask calls
    if check_bitmask_fields:
        field_arrays = find_field_arrays(filename, fields, items_defined)

    if label_vs_filter:
        matches = 0
        for hf in items_defined:
            if items_defined[hf].check_label_vs_filter(reportError=False):
                matches += 1

        # Only checking if almost every field does match.
        checking = len(items_defined) and matches<len(items_defined) and ((matches / len(items_defined)) > 0.9)
        if checking:
            print(filename, ':', matches, 'label-vs-filter matches of out of', len(items_defined), 'so reporting mismatches')
            for hf in items_defined:
                items_defined[hf].check_label_vs_filter(reportError=True)



#################################################################
# Main logic.

# command-line args.  Controls which dissector files should be checked.
# If no args given, will just scan epan/dissectors folder.
parser = argparse.ArgumentParser(description='Check calls in dissectors')
parser.add_argument('--file', action='append',
                    help='specify individual dissector file to test')
parser.add_argument('--folder', action='store', default='',
                    help='specify folder to test')
parser.add_argument('--commits', action='store',
                    help='last N commits to check')
parser.add_argument('--open', action='store_true',
                    help='check open files')
parser.add_argument('--mask', action='store_true',
                   help='when set, check mask field too')
parser.add_argument('--mask-exact-width', action='store_true',
                   help='when set, check width of mask against field width')
parser.add_argument('--label', action='store_true',
                   help='when set, check label field too')
parser.add_argument('--consecutive', action='store_true',
                    help='when set, copy copy/paste errors between consecutive items')
parser.add_argument('--missing-items', action='store_true',
                    help='when set, look for used items that were never registered')
parser.add_argument('--check-bitmask-fields', action='store_true',
                    help='when set, attempt to check arrays of hf items passed to add_bitmask() calls')
parser.add_argument('--label-vs-filter', action='store_true',
                    help='when set, check whether label matches last part of filter')
parser.add_argument('--all-checks', action='store_true',
                    help='when set, apply all checks to selected files')


args = parser.parse_args()

# Turn all checks on.
if args.all_checks:
    args.mask = True
    args.mask_exact_width = True
    args.consecutive = True
    args.check_bitmask_fields = True
    args.label_vs_filter = True


# Get files from wherever command-line args indicate.
files = []
if args.file:
    # Add specified file(s)
    for f in args.file:
        if not os.path.isfile(f):
            print('Chosen file', f, 'does not exist.')
            exit(1)
        else:
            files.append(f)
elif args.folder:
    # Add all files from a given folder.
    folder = args.folder
    if not os.path.isdir(folder):
        print('Folder', folder, 'not found!')
        exit(1)
    # Find files from folder.
    print('Looking for files in', folder)
    files = findDissectorFilesInFolder(folder, recursive=True)
elif args.commits:
    # Get files affected by specified number of commits.
    command = ['git', 'diff', '--name-only', '--diff-filter=d', 'HEAD~' + args.commits]
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Will examine dissector files only
    files = list(filter(lambda f : is_dissector_file(f), files))
elif args.open:
    # Unstaged changes.
    command = ['git', 'diff', '--name-only', '--diff-filter=d']
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Only interested in dissector files.
    files = list(filter(lambda f : is_dissector_file(f), files))
    # Staged changes.
    command = ['git', 'diff', '--staged', '--name-only', '--diff-filter=d']
    files_staged = [f.decode('utf-8')
                    for f in subprocess.check_output(command).splitlines()]
    # Only interested in dissector files.
    files_staged = list(filter(lambda f : is_dissector_file(f), files_staged))
    for f in files_staged:
        if not f in files:
            files.append(f)
else:
    # Find all dissector files.
    files  = findDissectorFilesInFolder(os.path.join('epan', 'dissectors'))
    files += findDissectorFilesInFolder(os.path.join('plugins', 'epan'), recursive=True)


# If scanning a subset of files, list them here.
print('Examining:')
if args.file or args.commits or args.open:
    if files:
        print(' '.join(files), '\n')
    else:
        print('No files to check.\n')
else:
    print('All dissector modules\n')


# Now check the files.
for f in files:
    if should_exit:
        exit(1)
    checkFile(f, check_mask=args.mask, mask_exact_width=args.mask_exact_width, check_label=args.label,
              check_consecutive=args.consecutive, check_missing_items=args.missing_items,
              check_bitmask_fields=args.check_bitmask_fields, label_vs_filter=args.label_vs_filter)

    # Do checks against all calls.
    if args.consecutive:
        combined_calls = CombinedCallsCheck(f, apiChecks)
        # This hasn't really found any issues, but shows lots of false positives (and are difficult to investigate)
        #combined_calls.check_consecutive_item_calls()


# Show summary.
print(warnings_found, 'warnings')
if errors_found:
    print(errors_found, 'errors')
    exit(1)
