(*
 * Copyright (c) 2014 Masoud Koleini <masoud.koleini@nottingham.ac.uk>
 * Copyright (c) 2011 Richard Mortier <mort@cantab.net>
 * Copyright (c) 2014 Charalampos Rotsos <cr409@cl.cam.ac.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open V1_LWT
open Lwt
open Packet


open OpenFlow0x04
open OpenFlow0x04_Core
(* open OpenFlow0x04_Stats *)

module Message = OpenFlow0x04.Message

exception Packet_type_unknw
exception Unparsable of string * Cstruct.t 
exception Unparsed of string * Cstruct.t 
exception Unsupported of string 

let sp = Printf.sprintf
let pp = Printf.printf
let ep = Printf.eprintf

type cookie = int64

let resolve t = Lwt.on_success t (fun _ -> ())

let get_new_buffer len = 
  let buf = Io_page.to_cstruct (Io_page.get 1) in 
    Cstruct.sub buf 0 len 

(* XXX check possible replacement *)
let or_error name fn t =
  fn t
  >>= function
	| `Error e -> fail (Failure ("Error starting " ^ name))
    | `Ok t -> let _ = (pp "%s works...\n" name) in
			   return t

module Entry = struct

  type table_counter = {
    n_active: int32;
    n_lookups: int64;
    n_matches: int64;
  }

  type flow_counter = {
    mutable n_packets: int64;
    mutable n_bytes: int64;
    flags : flowModFlags;
    priority: int16;
    cookie: cookie mask;
    insert_sec: int;
    insert_nsec: int;
    mutable last_sec: int;
    mutable last_nsec: int;
    idle_timeout: timeout;
    hard_timeout:timeout;
  }

  type queue_counter = {
    tx_queue_packets: int64;
    tx_queue_bytes: int64;
    tx_queue_overrun_errors: int64;
  }

(*
  (* XXX where is EMERG? *)
  let flags_to_int (check_overlap : bool) (notify_when_removed : bool) =
    (if check_overlap then 1 lsl 1 else 0) lor
      (if notify_when_removed then 1 lsl 0 else 0)

  let check_overlap_of_flags flags = 
    (1 lsl 1) land flags != 0

  let notify_when_removed_of_flags flags = 
    (1 lsl 0) land flags != 0
*)

  let init_flow_counters flowmod = (* we may require more information to save *)
    let ts = int_of_float (Clock.time ()) in
    ({n_packets=0L; n_bytes=0L;
	  priority=flowmod.mfPriority; cookie=flowmod.mfCookie;
	  insert_sec=ts; insert_nsec=0; (* XXX Do we need nsec? timeouts are in sec *)
	  last_sec=ts; last_nsec=0; idle_timeout=flowmod.mfIdle_timeout; hard_timeout=flowmod.mfHard_timeout;
	  flags=flowmod.mfFlags; })

  (* flow entry *)
  type t = { 
    mutable match_fields: OfpMatch.t list; (* eq to header fields in manual *)
    counters: flow_counter;
    instructions: instruction list;
  }

  let update_flow pkt_len flow = 
    flow.counters.n_packets <- Int64.add flow.counters.n_packets 1L;
    flow.counters.n_bytes <- Int64.add flow.counters.n_bytes pkt_len;
    flow.counters.last_sec <- int_of_float (Clock.time ())

  let flow_counters_to_flow_stats ofp_match table_id flow = (* return type: individualStats *)
   	{table_id
	; duration_sec = Int32.of_int (flow.counters.last_sec - flow.counters.insert_sec)
	; duration_nsec = Int32.of_int (flow.counters.last_nsec - flow.counters.insert_nsec)
	; priority = flow.counters.priority
	; idle_timeout = flow.counters.idle_timeout
	; hard_timeout = flow.counters.hard_timeout
	; flags = flow.counters.flags
	; cookie = flow.counters.cookie.m_value
	; packet_count = flow.counters.n_packets
	; byte_count = flow.counters.n_bytes
	; instructions = flow.instructions
	; ofp_match}

end


module SoxmMatch = struct

  cstruct dl_header {
    uint8_t   dl_dst[6];
    uint8_t   dl_src[6]; 
    uint16_t  dl_type 
  } as big_endian

  cstruct arphdr {
    uint16_t ar_hrd;         
    uint16_t ar_pro;         
    uint8_t ar_hln;              
    uint8_t ar_pln;              
    uint16_t ar_op;          
    uint8_t ar_sha[6];  
    uint32_t nw_src;
    uint8_t ar_tha[6];  
    uint32_t nw_dst 
  } as big_endian

  cstruct nw_header {
    uint8_t        hlen_version;
    uint8_t        nw_tos;
    uint16_t       total_len;
    uint8_t        pad[5];
    uint8_t        nw_proto; 
    uint16_t       csum;
    uint32_t       nw_src; 
    uint32_t       nw_dst
  } as big_endian 

  cstruct ipv6_header {
    uint32_t       version_class_flow;
    uint16_t       payload_len;
    uint8_t        next_header;
    uint8_t        hop_limit; 
    uint64_t       nw_src1;
    uint64_t       nw_src2; 
    uint64_t       nw_dst1;
    uint64_t       nw_dst2; 
  } as big_endian 

  cstruct tp_header {
    uint16_t tp_src;
    uint16_t tp_dst
  } as big_endian 

  cstruct icmphdr {
    uint8_t typ;
    uint8_t code;
    uint16_t checksum
  } as big_endian

  cstruct icmpv6_m135_m136 {
    uint32_t header;
    uint32_t res;
    uint64_t nw_dst1;
    uint64_t nw_dst2;
	uint32_t options;
  } as big_endian

  cstruct tcpv4 {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence;
    uint32_t ack_number;
    uint32_t  dataoff_flags_window;
    uint16_t checksum
  } as big_endian

  cstruct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t res;
    uint8_t proto;
    uint16_t len
  } as big_endian 

  type flow_info = (* XXX TODO: split it into sveral records of specific protocols *)
    {
      mutable inPort : portId (** Input switch port. *)
    ; mutable ethDst : dlAddr (** Etherent destination address. *)
	; mutable ethSrc : dlAddr (** Ethernet source address. *)
    ; mutable ethTyp : dlTyp (** Ethernet frame type. *)
    ; mutable dlVlan : dlVlan (** Input VLAN id. *)
    ; mutable dlVlanPcp : dlVlanPcp (** Input VLAN priority. *)
    ; mutable ipDSCP : int8 option (** IP DSCP (6 MSBs of ToS). *)
    ; mutable ipECN : int8 option (** IP ECN (2 LSBs of ToS). *)
    ; mutable ipProto : nwProto option (** IP protocol. *)
    ; mutable ipv4Src : nwAddr option (** IPv4 source address. *)
    ; mutable ipv4Dst : nwAddr option (** IPv4 destination address. *)
    ; mutable tcpSrc : int16 option (** TCP source port. *)
    ; mutable tcpDst : int16 option (** TCPdestination port. *)
    ; mutable udpSrc : int16 option (** UDP source port. *)
    ; mutable udpDst : int16 option (** UDP destination port. *)
    ; mutable sctpSrc : int16 option (** SCTP source port. *)
    ; mutable sctpDst : int16 option (** SCTP destination port. *)
    ; mutable icmpv4Type : int8 option (** ICMP Type. *)
    ; mutable icmpv4Code : int8 option (** ICMP Code. *)
	; mutable arpOpcode : int16 option (** ARP OpCode. *)
	; mutable arpSpa : int32 option (** ARP Source IPv4 Address in Payload. *)
	; mutable arpTpa : int32 option (** ARP target IPv4 Address in Payload. *)
	; mutable arpSha : dlAddr option (** ARP Source Ethernet Address in Payload. *)
	; mutable arpTha : dlAddr option (** ARP target Ethernet Address in Payload. *)
	; mutable ipv6Src : ipv6Addr option (** IPv6 source address. *)
	; mutable ipv6Dst : ipv6Addr option (** IPv6 destination address. *)
	; mutable ipv6flabel : int32 option (** IPv6 flow label. *)
    ; mutable icmpv6Type : int8 option (** ICMP Type. *)
    ; mutable icmpv6Code : int8 option (** ICMP Code. *)
	; mutable ipv6NDTarget : ipv6Addr option (** Target Address in IPV6 Neighbor Discovery Message **)
	; mutable ipv6NDSll : dlAddr option (** Source Link Layer Address in IPV6 Neighbor Discovery Message **)
	; mutable ipv6NDTll : dlAddr option (** Target Link Layer Address in IPV6 Neighbor Discovery Message **)
    }	

(*
  let match_to_flow_info of_match =
	let finfo = ref
			{ inPort = 0l
			; ethDst = 0L; ethSrc = 0L; ethTyp = 0
			; dlVlan = Some 0xffff (* TODO *)
			; dlVlanPcp = 0
			; ipv4Src = None; ipv4Dst = None; ipDSCP = None; ipECN = None; ipProto = None
			; tcpSrc = None; tcpDst = None; udpSrc = None; udpDst = None; sctpSrc = None
			; sctpDst = None; icmpv4Type = None; icmpv4Code = None; arpOpcode = None
			; arpSpa = None; arpTpa = None; arpSha = None; arpTha = None
			; ipv6Src = None; ipv6Dst = None; ipv6flabel = None; icmpv6Type = None
			; icmpv6Code = None; ipv6NDTarget = None; ipv6NDSll = None; ipv6NDTll = None }
	in
	let rec build_info of_match =
	match of_match with
	| [] -> return ()
	| (OxmInPort portId)::t -> finfo.inPort <- portId; build_info t
(*	| OxmInPhyPort of portId
	| OxmMetadata of int64 mask 
	| OxmEthType of int16
	| OxmEthDst of int48 mask
	| OxmEthSrc of int48 mask
	| OxmVlanVId of int12 mask
	| OxmVlanPcp of int8
	| OxmIPProto of int8
	| OxmIPDscp of int8
	| OxmIPEcn of int8
	| OxmIP4Src of int32 mask
	| OxmIP4Dst of int32 mask
	| OxmTCPSrc of int16
	| OxmTCPDst of int16
	| OxmARPOp of int16
	| OxmARPSpa of int32 mask
	| OxmARPTpa of int32 mask
	| OxmARPSha of int48 mask
	| OxmARPTha of int48 mask
	| OxmICMPType of int8
	| OxmICMPCode of int8
	| OxmMPLSLabel of int32
	| OxmMPLSTc of int8
	| OxmTunnelId of int64 mask
	| OxmUDPSrc of int16
	| OxmUDPDst of int16
	| OxmSCTPSrc of int16
	| OxmSCTPDst of int16
	| OxmIPv6Src of int128 mask
	| OxmIPv6Dst of int128 mask
	| OxmIPv6FLabel of int32 mask
	| OxmICMPv6Type of int8
	| OxmICMPv6Code of int8
	| OxmIPv6NDTarget of int128 mask
	| OxmIPv6NDSll of int48
	| OxmIPv6NDTll of int48
	| OxmMPLSBos of bool
	| OxmPBBIsid of int24 mask
	| OxmIPv6ExtHdr of oxmIPv6ExtHdr mask
*)
	in
	  build_info of_match
*)
  let oxm_to_num m =
	match m with
	| OxmInPort _ 		-> 0
	| OxmInPhyPort _	-> 1
	| OxmMetadata _		-> 2
	| OxmEthType _		-> 3
	| OxmEthDst _		-> 4
	| OxmEthSrc _		-> 5
	| OxmVlanVId _		-> 6
	| OxmVlanPcp _		-> 7
	| OxmIPProto _		-> 8
	| OxmIPDscp _		-> 9
	| OxmIPEcn _		-> 10
	| OxmIP4Src _		-> 11
	| OxmIP4Dst _		-> 12
	| OxmTCPSrc _		-> 13
	| OxmTCPDst _		-> 14
	| OxmARPOp _		-> 15
	| OxmARPSpa _		-> 16
	| OxmARPTpa _		-> 17
	| OxmARPSha _		-> 18
	| OxmARPTha _		-> 19
	| OxmICMPType _		-> 20
	| OxmICMPCode _		-> 21
	| OxmMPLSLabel _	-> 22
	| OxmMPLSTc _		-> 23
	| OxmTunnelId _		-> 24
	| OxmUDPSrc _		-> 25
	| OxmUDPDst _		-> 26
	| OxmSCTPSrc _		-> 27
	| OxmSCTPDst _		-> 28
	| OxmIPv6Src _		-> 29
	| OxmIPv6Dst _		-> 30
	| OxmIPv6FLabel _	-> 31
	| OxmICMPv6Type _	-> 32
	| OxmICMPv6Code _	-> 33
	| OxmIPv6NDTarget _	-> 34
	| OxmIPv6NDSll _	-> 35
	| OxmIPv6NDTll _	-> 36
	| OxmMPLSBos _		-> 37
	| OxmPBBIsid _		-> 38
	| OxmIPv6ExtHdr _	-> 39

  (* TODO: sort ofpMatch sent by controller before any processing ... *)
  let sort_of_match m1 m2 = (oxm_to_num m1) - (oxm_to_num m2)

(*
  let raw_packet_to_flow in_port bits =
	let ethDst = Packet.mac_of_bytes (Cstruct.to_string (get_dl_header_dl_dst bits)) in
    let ethSrc = Packet.mac_of_bytes (Cstruct.to_string (get_dl_header_dl_src bits)) in
    let eth_type = get_dl_header_dl_type bits in
    let bits = Cstruct.shift bits sizeof_dl_header in 
    match (eth_type) with 
    | 0x0800 -> begin (* IPv4 *)
      let nw_src = get_nw_header_nw_src bits in 
      let nw_dst = get_nw_header_nw_dst bits in 
      let nw_proto = get_nw_header_nw_proto bits in 
      let nw_tos = get_nw_header_nw_tos bits in 
      let len = (get_nw_header_hlen_version bits) land 0xf in 
      let bits = Cstruct.shift bits (len*4) in
	  let tcpSrc, tcpDst, udpSrc, udpDst, sctpSrc, sctpDst,
			icmpv4Type, icmpv4Code, icmpv6Type, icmpv6Code,
			ipv6NDTarget, ipv6NDSll, ipv6NDTll =
			ref None, ref None, ref None, ref None, ref None, ref None,
			ref None, ref None, ref None, ref None,
			ref None, ref None, ref None in
	  let _ =
        match (nw_proto) with
        | 1  -> icmpv4Type := Some (get_icmphdr_typ bits); icmpv4Code := Some (get_icmphdr_code bits);
        | 6  -> tcpSrc := Some (get_tp_header_tp_src bits); tcpDst := Some (get_tp_header_tp_dst bits);
        | 17 -> udpSrc := Some (get_tp_header_tp_src bits); udpSrc := Some (get_tp_header_tp_dst bits);
        | 58 -> let typ = get_icmphdr_typ bits in
				icmpv6Type := Some typ; icmpv6Code := Some (get_icmphdr_code bits);
				match typ with
				| 135 -> ipv6NDTarget := Some (get_icmpv6_m135_m136_nw_dst1 bits, get_icmpv6_m135_m136_nw_dst2 bits);
				(* TODO ipv6NDSll *)
				| 136 -> ipv6NDTarget := Some (get_icmpv6_m135_m136_nw_dst1 bits, get_icmpv6_m135_m136_nw_dst2 bits);
				(* TODO ipv6NDTll *)
		| 132-> sctpSrc := Some (get_tp_header_tp_src bits); sctpDst := Some (get_tp_header_tp_dst bits);
		in 
			{ inPort = in_port
			; ethDst; ethSrc
			; ethTyp = eth_type
			; dlVlan = Some 0xffff (* TODO *)
			; dlVlanPcp = 0
			; ipv4Src = Some nw_src (* XXX change type? *)
			; ipv4Dst = Some nw_dst
			; ipDSCP = Some (nw_tos lsr 2)
			; ipECN = Some (nw_tos land 3)
			; ipProto = Some nw_proto
			; tcpSrc = !tcpSrc; tcpDst = !tcpDst; udpSrc = !udpSrc; udpDst = !udpDst
			; sctpSrc = !sctpSrc; sctpDst = !sctpDst; icmpv4Type = !icmpv4Type; icmpv4Code = !icmpv4Code
			; arpOpcode = None; arpSpa = None; arpTpa = None; arpSha = None; arpTha = None
			; ipv6Src = None; ipv6Dst = None; ipv6flabel = None
			; icmpv6Type = !icmpv6Type; icmpv6Code = !icmpv6Code
			; ipv6NDTarget = !ipv6NDTarget; ipv6NDSll = !ipv6NDSll; ipv6NDTll = !ipv6NDTll }
      end
    | 0x86dd -> (* IPv6 : TODO *)
		{ inPort = in_port
		; ethDst; ethSrc
		; ethTyp = eth_type
		; dlVlan = (Some 0xffff)
		; dlVlanPcp = 0
		; ipv4Src = None; ipv4Dst = None; ipDSCP = None; ipECN = None; ipProto = None
		; tcpSrc = None; tcpDst = None; udpSrc = None; udpDst = None
		; sctpSrc = None; sctpDst = None; icmpv4Type = None; icmpv4Code = None
		; arpOpcode = None; arpSpa = None; arpTpa = None; arpSha = None; arpTha = None
		; ipv6Src = Some (get_ipv6_header_nw_src1 bits, get_ipv6_header_nw_src2 bits)
		; ipv6Dst = Some (get_ipv6_header_nw_dst1 bits, get_ipv6_header_nw_dst2 bits)
		; ipv6flabel = Some (Int32.logand (get_ipv6_header_version_class_flow bits) (Int32.of_int 0xfffff))
		; icmpv6Type = None; icmpv6Code = None
		; ipv6NDTarget = None; ipv6NDSll = None; ipv6NDTll = None } 
    | 0x0806 -> (* ARP :TODO *)
		{ inPort = in_port 
		; ethDst; ethSrc
		; ethTyp = eth_type
		; dlVlan = (Some 0xffff)
		; dlVlanPcp = 0
		; ipv4Src = None; ipv4Dst = None; ipDSCP = None; ipECN = None; ipProto = None
		; tcpSrc = None; tcpDst = None; udpSrc = None; udpDst = None
		; sctpSrc = None; sctpDst = None; icmpv4Type = None; icmpv4Code = None
		; arpOpcode = Some (get_arphdr_ar_op bits)
		; arpSpa = Some (get_arphdr_nw_src bits)
		; arpTpa = Some (get_arphdr_nw_dst bits)
		; arpSha = Some (Packet.mac_of_bytes (Cstruct.to_string (get_arphdr_ar_sha bits)))
		; arpTha = Some (Packet.mac_of_bytes (Cstruct.to_string (get_arphdr_ar_tha bits)))
		; ipv6Src = None; ipv6Dst = None; ipv6flabel = None
		; icmpv6Type = None; icmpv6Code = None
		; ipv6NDTarget = None; ipv6NDSll = None; ipv6NDTll = None } 
    | _ ->  (* TODO MPLS and ... *)
		{ inPort = in_port 
		; ethDst; ethSrc
		; ethTyp = eth_type
		; dlVlan = (Some 0xffff)
		; dlVlanPcp = 0
		; ipv4Src = None; ipv4Dst = None; ipDSCP = None; ipECN = None; ipProto = None
		; tcpSrc = None; tcpDst = None; udpSrc = None; udpDst = None
		; sctpSrc = None; sctpDst = None; icmpv4Type = None; icmpv4Code = None
		; arpOpcode = None; arpSpa = None; arpTpa = None; arpSha = None; arpTha = None
		; ipv6Src = None; ipv6Dst = None; ipv6flabel = None
		; icmpv6Type = None; icmpv6Code = None
		; ipv6NDTarget = None; ipv6NDSll = None; ipv6NDTll = None } 
*)

  let raw_packet_to_match in_port bits = (* builds openflow match in order *)
	let ethDst = Packet.mac_of_bytes (Cstruct.to_string (get_dl_header_dl_dst bits)) in
    let ethSrc = Packet.mac_of_bytes (Cstruct.to_string (get_dl_header_dl_src bits)) in
    let eth_type = get_dl_header_dl_type bits in
    let bits = Cstruct.shift bits sizeof_dl_header in 
	let network = [OxmInPort in_port; OxmEthType eth_type;
				   OxmEthDst (val_to_mask ethDst); OxmEthSrc (val_to_mask ethSrc)] in
    match (eth_type) with 
    | 0x0800 -> begin (* IPv4 *)
      let nw_src = get_nw_header_nw_src bits in 
      let nw_dst = get_nw_header_nw_dst bits in 
      let nw_proto = get_nw_header_nw_proto bits in 
      let nw_tos = get_nw_header_nw_tos bits in 
      let len = (get_nw_header_hlen_version bits) land 0xf in 
      let bits = Cstruct.shift bits (len*4) in
	  let network_ip =
			network @ [OxmIPProto nw_proto; OxmIPDscp (nw_tos lsr 2); OxmIPEcn (nw_tos land 3);
					   OxmIP4Src (val_to_mask nw_src); OxmIP4Dst (val_to_mask nw_dst);]
	  in
	    network_ip @ (
        match (nw_proto) with
        | 1  -> [OxmICMPType (get_icmphdr_typ bits); OxmICMPCode (get_icmphdr_code bits)]
        | 6  -> [OxmTCPSrc (get_tp_header_tp_src bits); OxmTCPDst (get_tp_header_tp_dst bits)]
        | 17 -> [OxmUDPSrc (get_tp_header_tp_src bits); OxmUDPDst (get_tp_header_tp_dst bits)]
        | 58 -> let typ = get_icmphdr_typ bits in
				[OxmICMPv6Type typ; OxmICMPv6Code (get_icmphdr_code bits)] @ (
				match typ with
				| 135 -> let ipv6NDTarget = (get_icmpv6_m135_m136_nw_dst1 bits, get_icmpv6_m135_m136_nw_dst2 bits) in
					[OxmIPv6NDTarget (val_to_mask ipv6NDTarget)]
				(* TODO ipv6NDSll *)
				| 136 -> let ipv6NDTarget = (get_icmpv6_m135_m136_nw_dst1 bits, get_icmpv6_m135_m136_nw_dst2 bits) in
					[OxmIPv6NDTarget (val_to_mask ipv6NDTarget)]
				(* TODO ipv6NDTll *)
				)
		| 132-> [OxmSCTPSrc (get_tp_header_tp_src bits); OxmSCTPDst (get_tp_header_tp_dst bits)]
		(* TODO | _ -> raise error *)
		)
      end 
    | 0x86dd -> (* IPv6 : TODO *)
		network @ [
		  OxmIPv6Src (val_to_mask (get_ipv6_header_nw_src1 bits, get_ipv6_header_nw_src2 bits))
		; OxmIPv6Dst (val_to_mask (get_ipv6_header_nw_dst1 bits, get_ipv6_header_nw_dst2 bits))
		; OxmIPv6FLabel (val_to_mask (Int32.logand (get_ipv6_header_version_class_flow bits) (Int32.of_int 0xfffff)))
		]
    | 0x0806 -> (* ARP :TODO *)
		network @ [
		  OxmARPOp (get_arphdr_ar_op bits)
		; OxmARPSpa (val_to_mask (get_arphdr_nw_src bits))
		; OxmARPTpa (val_to_mask (get_arphdr_nw_dst bits))
		; OxmARPSha (val_to_mask (Packet.mac_of_bytes (Cstruct.to_string (get_arphdr_ar_sha bits))))
		; OxmARPTha (val_to_mask (Packet.mac_of_bytes (Cstruct.to_string (get_arphdr_ar_tha bits))))
		]
    | _ ->  (* TODO MPLS and ... *)
		network
(*
  let rec flow_match_compare flow flow_patten =
	let check_with_mask f f_p l_and =
	  match f, f_p with
	  | v, {m_value = v_p; m_mask = None} -> v = v_p
	  | v, {m_value = v_p; m_mask = Some m} -> (l_and v m) = (l_and v_p m)
	in
	let compare f f_p =
	  match f, f_p with
	  | Some x, y -> x = y
	  | None, _ -> false
	in
	let check cond t =
		if cond then flow_match_compare flow t else false
	in
	  match flow_patten with
	  | [] -> true
	  | h::t -> match h with
		| OxmInPort portId -> check (flow.inPort = portId) t
		(* | OxmInPhyPort portId -> *)
		(* | OxmMetadata of int64 mask *)
		| OxmEthType ethType -> check (flow.ethTyp = ethType) t
		| OxmEthDst ethDst -> check (check_with_mask flow.ethDst ethDst Int64.logand) t
		| OxmEthSrc ethSrc -> check (check_with_mask flow.ethSrc ethSrc Int64.logand) t
		(* | OxmVlanVId of int12 mask *)
		(* | OxmVlanPcp of int8 *)
		| OxmIPProto ipProto -> check (compare flow.ipProto ipProto) t
		| OxmIPDscp ipDSCP -> check (compare flow.ipDSCP ipDSCP) t
		| OxmIPEcn ipECN -> check (compare flow.ipECN ipECN) t
		| OxmIP4Src ipv4Src -> begin
							   match flow.ipv4Src with
								| None -> check true t
								| Some x -> check (check_with_mask x ipv4Src Int32.logand) t
							   end
		| OxmIP4Dst ipv4Dst -> begin
							   match flow.ipv4Dst with
								| None -> check true t
								| Some x -> check (check_with_mask x ipv4Dst Int32.logand) t
							   end
		| OxmTCPSrc tcpSrc -> check (compare flow.tcpSrc tcpSrc) t
		| OxmTCPDst tcpDst -> check (compare flow.tcpDst tcpDst) t
		| OxmARPOp arpOpcode -> check (compare flow.arpOpcode arpOpcode) t 
		| OxmARPSpa arpSpa -> begin
							   match flow.arpSpa with
								| None -> check true t
								| Some x -> check (check_with_mask x arpSpa Int32.logand) t
							   end
 		| OxmARPTpa arpTpa -> begin
							   match flow.arpTpa with
								| None -> check true t
								| Some x -> check (check_with_mask x arpTpa Int32.logand) t
							   end
		| OxmARPSha arpSha -> begin
							   match flow.arpSha with
								| None -> check true t
								| Some x -> check (check_with_mask x arpSha Int64.logand) t
							   end
		| OxmARPTha arpTha -> begin
							   match flow.arpTha with
								| None -> check true t
								| Some x -> check (check_with_mask x arpTha Int64.logand) t
							   end
		| OxmICMPType icmpv4Type -> check (compare flow.icmpv4Type icmpv4Type) t
		| OxmICMPCode icmpv4Code -> check (compare flow.icmpv4Code icmpv4Code) t
(*		| OxmMPLSLabel of int32
		| OxmMPLSTc of int8
		| OxmTunnelId of int64 mask *)
		| OxmUDPSrc udpSrc -> check (compare flow.udpSrc udpSrc) t
		| OxmUDPDst udpDts -> check (compare flow.udpDst udpDts) t 
		| OxmSCTPSrc tcpSrc -> check (compare flow.tcpSrc tcpSrc) t
		| OxmSCTPDst tcpDst -> check (compare flow.tcpDst tcpDst) t
(*		| OxmIPv6Src ipv6Src ->  begin
							   match flow.ipv6Src with
								| None -> check true t
								| Some x -> check (check_with_mask128 x ipv6Src) t
							   end
		| OxmIPv6Dst of int128 mask *)
		| OxmIPv6FLabel ipv6flabel -> begin
							   match flow.ipv6flabel with
								| None -> check true t
								| Some x -> check (check_with_mask x ipv6flabel Int32.logand) t
							   end
		| OxmICMPv6Type icmpv6Type -> check (compare flow.icmpv6Type icmpv6Type) t
		| OxmICMPv6Code icmpv6Code -> check (compare flow.icmpv6Code icmpv6Code) t
(*		| OxmIPv6NDTarget of int128 mask
		| OxmIPv6NDSll of int48
		| OxmIPv6NDTll of int48
		| OxmMPLSBos of bool
		| OxmPBBIsid of int24 mask
		| OxmIPv6ExtHdr of oxmIPv6ExtHdr mask
*)
*)
  (* XXX considering that of_match lists are ordered in the same way *)
  let rec check_flow_overlap flow flow_patten =
	let check_with_mask f f_p logical_and =
	  match f, f_p with (* definition of mask is changed in openflow 1.4.0 *)
	  | {m_value = v; m_mask = None}, {m_value = v_p; m_mask = None} -> v = v_p
	  | {m_value = v; m_mask = Some m}, {m_value = v_p; m_mask = Some m_p} ->
		  (logical_and v m) = (logical_and v_p m_p)
	  | _, _ -> false
	in
	let check cond tx ty =
		if cond then check_flow_overlap tx ty else false
	in
	match flow, flow_patten with
	| [], _ | _, [] -> true

	| (OxmInPort x)::tx, (OxmInPort y)::ty
	| (OxmInPhyPort x)::tx, (OxmInPhyPort y)::ty 
	| (OxmMPLSLabel x)::tx, (OxmMPLSLabel y)::ty
		-> check (x = y) tx ty
	| (OxmEthType x)::tx, (OxmEthType y)::ty
	| (OxmTCPSrc x)::tx, (OxmTCPSrc y)::ty
	| (OxmTCPDst x)::tx, (OxmTCPDst y)::ty
	| (OxmARPOp x)::tx, (OxmARPOp y)::ty
	| (OxmICMPType x)::tx, (OxmICMPType y)::ty
	| (OxmICMPCode x)::tx, (OxmICMPCode y)::ty
	| (OxmMPLSTc x)::tx, (OxmMPLSTc y)::ty
	| (OxmUDPSrc x)::tx, (OxmUDPSrc y)::ty
	| (OxmUDPDst x)::tx, (OxmUDPDst y)::ty
	| (OxmSCTPSrc x)::tx, (OxmSCTPSrc y)::ty
	| (OxmSCTPDst x)::tx, (OxmSCTPDst y)::ty
	| (OxmICMPv6Type x)::tx, (OxmICMPv6Type y)::ty
	| (OxmICMPv6Code x)::tx, (OxmICMPv6Code y)::ty
		-> check (x = y) tx ty
	| (OxmEthDst x)::tx, (OxmEthDst y)::ty 
	| (OxmEthSrc x)::tx, (OxmEthSrc y)::ty 
	| (OxmARPSha x)::tx, (OxmARPSha y)::ty 
	| (OxmARPTha x)::tx, (OxmARPTha y)::ty
	| (OxmTunnelId x)::tx, (OxmTunnelId y)::ty
		-> check (check_with_mask x y Int64.logand) tx ty
	| (OxmVlanPcp x)::tx, (OxmVlanPcp y)::ty
	| (OxmIPProto x)::tx, (OxmIPProto y)::ty
	| (OxmIPDscp x)::tx, (OxmIPDscp y)::ty
	| (OxmIPEcn x)::tx, (OxmIPEcn y)::ty
		-> check (x = y) tx ty
	| (OxmIP4Src x)::tx, (OxmIP4Src y)::ty 
	| (OxmIP4Dst x)::tx, (OxmIP4Dst y)::ty 
	| (OxmARPSpa x)::tx, (OxmARPSpa y)::ty 
	| (OxmARPTpa x)::tx, (OxmARPTpa y)::ty 
	| (OxmIPv6FLabel x)::tx, (OxmIPv6FLabel y)::ty 
	| (OxmPBBIsid x)::tx, (OxmPBBIsid y)::ty 
		-> check (check_with_mask x y Int32.logand) tx ty
	| (OxmIPv6NDSll x)::tx, (OxmIPv6NDSll y)::ty
	| (OxmIPv6NDTll x)::tx, (OxmIPv6NDTll y)::ty
		-> check (x = y) tx ty
	| (OxmMPLSBos x)::tx, (OxmMPLSBos y)::ty
		-> check (x = y) tx ty
(*	| (OxmVlanVId x)::tx, (OxmVlanVId y)::ty
		-> false
	| (OxmIPv6Src x)::tx, (OxmIPv6Src y)::ty
	| (OxmIPv6Dst x)::tx, (OxmIPv6Dst y)::ty
		-> false
	| (OxmIPv6NDTarget x)::tx, (OxmIPv6NDTarget y)::ty
		-> false *)
	| ofmx::tx, ofmy::ty -> if (oxm_to_num ofmx) < (oxm_to_num ofmy) then
								check_flow_overlap tx flow_patten
							else
								check_flow_overlap flow ty
	(* oxmIPv6ExtHdr? *)

end

module Make(T:TCPV4 (* controller *))(N:NETWORK) = struct

  module E = Ethif.Make(N)
  module Channel = Channel.Make(T)
  module OSK = Ofsocket0x04.Make(T)

  type eth_t = E.t 

(*  type port_stats = {
	mutable port_id : int16;
	mutable rx_packets : int64;
	mutable tx_packets : int64;
	mutable rx_bytes : int64;
	mutable tx_bytes : int64;
	mutable rx_dropped : int64;
	mutable tx_dropped : int64;
	mutable rx_errors : int64;
	mutable tx_errors : int64;
	mutable rx_frame_err : int64;
	mutable rx_over_err : int64;
	mutable rx_crc_err : int64;
	mutable collisions : int64;
  }
*)

  type port = {
    port_id: portId;
    ethif: E.t;
    port_name: string;
    mutable counter: portStats;
    phy: portDesc;
    in_queue: Cstruct.t Lwt_stream.t;
    in_push : (Cstruct.t option -> unit);
    out_queue: Cstruct.t Lwt_stream.t;
    out_push : (Cstruct.t option -> unit);
    mutable pkt_count : int;
  }

  module Table = struct
	type t = {
	  tid: tableId; (* XXX why we have cookie in both table and entry module? Do we need it for Table? *)

	  (* This entry stores wildcard and exact match entries as
	   * transmitted by the controller *)

	  (* XXX each entry contains a list of header fields. Why we have one per entry here? *)
	  (* mutable entries: (OfpMatch.t, Entry.t) Hashtbl.t; *)
	  mutable entries: (OfpMatch.t, Entry.t) Hashtbl.t;

	  (* Intermediate table to store exact match flows deriving from wildcard
	   * entries *)

	  (* XXX each entry contains a list of header fields. Why we have one per entry here? *)
	  mutable cache : (OfpMatch.t, Entry.t ref) Hashtbl.t;
	  (* stats : OP.Stats.table; *) (* removed for now *)
	}

	let init_table () = 
		{ tid = 0; entries = (Hashtbl.create 10000); cache = (Hashtbl.create 10000);} (* XXX tid 0 *)

	(* TODO fix flow_mod flag support. overlap is not considered *)
	(* XXX st as argument is never used in Table functions *)
	let add_flow st table (fm : flowMod) verbose =
		(* TODO check if the details are correct e.g. IP type etc. *)
		let priority =
		  (* max priority for exact match rules *)
		  (* if  ((wildcards_of_match t) ={
    in_port = false; dl_vlan: false; dl_src: false; dl_dst: false; dl_type: false; nw_proto: false;
    tp_src: false; tp_dst: false; nw_src: 0; nw_dst: 0; dl_vlan_pcp: false; nw_tos: false;}) then *)
		    0x1001 (* XXX important: check it *)
		in
		let entry = Entry.({
					  instructions=fm.mfInstructions
					; counters=(init_flow_counters fm)
					; match_fields=[] (* XXX check the usage *)
					}) in  
		let _ = Hashtbl.replace table.entries fm.mfOfp_match entry in
									(* important: lists with different ordering
										will become diffent keys. Change list to set? *)
		(* In the fast path table, I need to delete any conflicting entries *)
		let _ = 
		  Hashtbl.iter (
		    fun a e -> 
		      if ((SoxmMatch.check_flow_overlap a fm.mfOfp_match) && (* how to find? *)
		          Entry.(entry.counters.priority >= (!e).counters.priority)) then ( 
		            let _ = (!e).Entry.match_fields <- 
		              List.filter (fun c -> a <> c) (!e).Entry.match_fields in 
		            let _ = Hashtbl.replace table.cache a (ref entry) in 
		              entry.Entry.match_fields <- a :: entry.Entry.match_fields
		          )
		  ) table.cache in
		let _ = if (verbose) then 
		  pp "[switch] Adding flow %s\n" (OfpMatch.to_string fm.mfOfp_match)
		in
		  return ()

	  (* check if a list of actions has an output action forwarding packets to
	   * out_port.
	   * Used when removing a port from the switch control in order to clean related
	   * flows *)

  let rec is_output_port out_port = 
	let rec is_output = function
		| [] -> false
		| Output (PhysicalPort portId) ::_ when (portId = out_port) -> true
		| h::t -> is_output t
	in
	function 
	| [] -> false
	| (ApplyActions h)::t -> if is_output h then true else is_output_port out_port t 
	| _::t -> is_output_port out_port t


  let marshal_optional t = match t with (* from OF *)
    | None -> 0xffffl (* OFPP_NONE *)
    | Some x -> PseudoPort.marshal x

  let del_flow table ?(xid=(Random.int32 Int32.max_int)) 
        ?(reason=FlowDelete) dflow out_port t verbose =

	let port_num = marshal_optional out_port in
    (* Delete all matching entries from the flow table*)
    let remove_flow = 
      Hashtbl.fold (
        fun of_match flow ret -> 
          if ((SoxmMatch.check_flow_overlap of_match dflow) && 
              ((port_num = 0xffffl) ||  (* XXX we don't have this type in OF_Core *)
               (is_output_port port_num flow.Entry.instructions))) then ( 
            let _ = Hashtbl.remove table.entries of_match in 
            (* log removal of flow *)
(*            let _ = 
              match Lwt.get OS.Topology.node_name with
              | None -> ()
              | Some(node_name) -> 
                  let flow_str = OP.Match.match_to_string of_match in
                  let action_str = OP.Flow.string_of_actions flow.Entry.actions in
                  let msg = Rpc.Dict [ 
                    ("name", (Rpc.String node_name));
                    ("type", (Rpc.String "del"));
                    ("flow", (Rpc.String flow_str)); 
                    ("action", (Rpc.String action_str));] in
                    OS.Console.broadcast "flow" (Jsonrpc.to_string msg)
    in *)
               (of_match, flow)::ret
          ) else ret
          ) table.entries [] in

    (* Delete all entries from cache *) 
    let _ = 
      List.iter (
        fun (_, flow) -> 
          List.iter (Hashtbl.remove table.cache) flow.Entry.match_fields
      ) remove_flow in 

    (* Check for notification flag in flow and send 
    * flow modification warnings *)
      Lwt_list.iter_s (
      fun (of_match, flow) ->
        let _ = 
          if verbose then
            pp "[switch] Removing flow %s" (OfpMatch.to_string of_match)
        in 
        match(t, flow.Entry.counters.flags.fmf_send_flow_rem (*.OP.Flow_mod.send_flow_rem *)) with
        | (Some t, true) -> 
          let duration_sec = (int_of_float (Clock.time ()))  -
            flow.Entry.counters.Entry.insert_sec in
          let fl_rm = (
			{ cookie = flow.Entry.counters.Entry.cookie.m_value
			; priority = flow.Entry.counters.Entry.priority
			; reason
			; table_id = table.tid
			; duration_sec = (Int32.of_int duration_sec)
			; duration_nsec = 0l
			; idle_timeout = flow.Entry.counters.Entry.idle_timeout
			; hard_timeout = flow.Entry.counters.Entry.hard_timeout
			; packet_count = flow.Entry.counters.Entry.n_packets
			; byte_count = flow.Entry.counters.Entry.n_bytes
			; oxm = of_match }
		) in
			OSK.send_packet t (Message.marshal xid (FlowRemoved fl_rm))
        | _ -> return ()
    ) remove_flow
(*
(*	return *)


	(* table stat update methods *)
(*
	let update_table_found table =
	  let open OP.Stats in 
		table.stats.lookup_count <- Int64.add table.stats.lookup_count 1L;
		table.stats.matched_count <- Int64.add table.stats.matched_count 1L

	let update_table_missed table =
	  let open OP.Stats in 
		table.stats.lookup_count <- Int64.add table.stats.lookup_count 1L
*)	
	  (* monitor thread to timeout flows *)
	let monitor_flow_timeout table t verbose = 
	  let open Entry in
		let check_flow_timeout table t verbose = 
		  let ts = int_of_float (Clock.time ()) in 
		  let flows = Hashtbl.fold (
		    fun of_match entry ret -> 
		      let hard = ts - entry.counters.insert_sec in
		      let idle = ts - entry.counters.last_sec in
		      match (hard, idle) with 
		        | (l, _) when ((Timeout.to_int entry.counters.hard_timeout > 0) && 
		                       (l >= Timeout.to_int entry.counters.hard_timeout)) ->
		            (of_match, entry, HardTimeout )::ret
		        | (_, l) when ((Timeout.to_int entry.counters.idle_timeout > 0) &&
		                       (l >= Timeout.to_int entry.counters.idle_timeout)) ->
		            ret @ [(of_match, entry, IdleTimeout )]
		        | _ -> ret 
		  ) table.entries [] in 
		    Lwt_list.iter_s (
		      fun (of_match, entry, reason) -> 
		        del_flow table ~reason of_match None (* output port *) t verbose (* XXX important: check *)
		    ) flows
		in
		while_lwt true do 
		  lwt _ = OS.Time.sleep 1.0 in 
		    check_flow_timeout table t verbose 
		done 
*)
	end
  (* end of module table *)

  let init_port port_no ethif =
    let name = "" in (* XXX TODO *)
	let hw_addr = Packet.mac_of_string (Macaddr.to_string (E.mac ethif)) in
    let (in_queue, in_push) = Lwt_stream.create () in
    let (out_queue, out_push) = Lwt_stream.create () in
    let counter = 
        { psPort_no=port_no; rx_packets=0L; tx_packets=0L; rx_bytes=0L; 
          tx_bytes=0L; rx_dropped=0L; tx_dropped=0L; rx_errors=0L; 
          tx_errors=0L; rx_frame_err=0L; rx_over_err=0L; rx_crc_err=0L; 
          collisions=0L; duration_sec=0l; duration_nsec=0l}
	in
    let features = (* XXX check: all rates are set to true *)
		{ rate_10mb_hd=true; rate_10mb_fd=true; rate_100mb_hd=true; rate_100mb_fd=true;
      	  rate_1gb_hd=true; rate_1gb_fd=true; rate_10gb_fd=true; rate_40gb_fd=true;
      	  rate_100gb_fd=true; rate_1tb_fd=true; other=true; copper=true; fiber=true;
      	  autoneg=true; pause=true; pause_asym=true }  
	in
    let config = { port_down=false; no_recv=false; no_fwd=false; no_packet_in=false } in 
    let state = { link_down=false; blocked=false; live=true } in (* XXX check liveness *)
    let phy = 
		{ port_no; hw_addr; name; config; 
          state; curr=features; advertised=features;
		  supported=features; peer=features;
          curr_speed=0x3ffl; max_speed=0xfffffl}
	in
    {port_id=port_no; port_name=name; counter; 
	 ethif=ethif; phy; in_queue; in_push; pkt_count=0;
	 out_queue; out_push;}

  type stats = {
    mutable n_frags: int64;
    mutable n_hits: int64;
    mutable n_missed: int64;
    mutable n_lost: int64;
  }

  type lookup_ret = 
         Found of Entry.t ref
       | NOT_FOUND

  type t' = {
    (* Mapping Netif objects to ports *) (* XXX each port has Netif record, do we need it here anymore? *)
    (* mutable dev_to_port: (Net.Manager.id, port ref) Hashtbl.t; *)
    (* Mapping port ids to port numbers *)
    mutable int_to_port: (int32, port ref) Hashtbl.t;
    mutable ports : port list;
    mutable controller: OSK.conn_state option;
    mutable last_echo_req : float;
    mutable echo_resp_received : bool;
    table: Table.t list;
    stats: stats;
    mutable errornum : int32;
    mutable portnum : int32;
    mutable features' : SwitchFeatures.t;
    mutable packet_buffer: PacketIn.t list; (* OP.Packet_in.t list; *)
    mutable packet_buffer_id: int32;
    ready : unit Lwt_condition.t;
    verbose : bool;
    mutable pkt_len : int;
  }
(*
 let supported_actions () =
   SwitchFeatures.SupportedActions.({ output=true; set_vlan_id=true; set_vlan_pcp=true; strip_vlan=true;
   set_dl_src=true; set_dl_dst=true; set_nw_src=true; set_nw_dst=true;
   set_nw_tos=true; set_tp_src=true; set_tp_dst=true; enqueue=false;vendor=true; })
*)

  let supported_capabilities () = 
	{ flow_stats=true; table_stats=true; port_stats=true
	; group_stats=true; ip_reasm=false; queue_stats=false
	; port_blocked=false } (* XXX check queue_stats and port_blocked *)

  let switch_features datapath_id = 
	SwitchFeatures.({
	  datapath_id; num_buffers=0l; num_tables=1; aux_id=0; (* XXX check aux *)
      supported_capabilities=(supported_capabilities ())})

  let update_port_tx_stats pkt_len (port : port)=
	port.counter <-
		{ psPort_no = port.counter.psPort_no
		; rx_packets = port.counter.rx_packets
		; tx_packets = (Int64.add port.counter.tx_packets 1L)
		; rx_bytes = port.counter.rx_bytes
		; tx_bytes = (Int64.add port.counter.tx_bytes pkt_len)
		; rx_dropped = port.counter.rx_dropped
		; tx_dropped = port.counter.tx_dropped
		; rx_errors = port.counter.rx_errors
		; tx_errors = port.counter.tx_errors
		; rx_frame_err = port.counter.rx_frame_err
		; rx_over_err = port.counter.rx_over_err
		; rx_crc_err = port.counter.rx_crc_err
		; collisions = port.counter.collisions
		; duration_sec = port.counter.duration_sec
		; duration_nsec = port.counter.duration_nsec}

  let update_port_rx_stats pkt_len (port : port) = 
	port.counter <-
		{ psPort_no = port.counter.psPort_no
		; rx_packets = Int64.add port.counter.rx_packets 1L
		; tx_packets = port.counter.tx_packets
		; rx_bytes = Int64.add port.counter.rx_bytes pkt_len
		; tx_bytes = port.counter.tx_bytes
		; rx_dropped = port.counter.rx_dropped
		; tx_dropped = port.counter.tx_dropped
		; rx_errors = port.counter.rx_errors
		; tx_errors = port.counter.tx_errors
		; rx_frame_err = port.counter.rx_frame_err
		; rx_over_err = port.counter.rx_over_err
		; rx_crc_err = port.counter.rx_crc_err
		; collisions = port.counter.collisions
		; duration_sec = port.counter.duration_sec
		; duration_nsec = port.counter.duration_nsec}

  (* we have exactly the same function in pcb.mli *)
  let tcp_checksum ~src ~dst =
	let open SoxmMatch in
    let pbuf = Cstruct.sub (Cstruct.of_bigarray (Io_page.get 1)) 0 sizeof_pseudo_header in
    fun data ->
      set_pseudo_header_src pbuf (Ipaddr.V4.to_int32 src);
      set_pseudo_header_dst pbuf (Ipaddr.V4.to_int32 dst);
      set_pseudo_header_res pbuf 0;
      set_pseudo_header_proto pbuf 6;
      set_pseudo_header_len pbuf (Cstruct.lenv data);
      Tcpip_checksum.ones_complement_list (pbuf::data)

  let send_frame (port : port) bits =
    update_port_tx_stats (Int64.of_int (Cstruct.len bits)) port;
    return (port.out_push (Some bits))

  let forward_frame (st : t') (* it has controller *) in_port bits checksum port (* output port *)
			table cookie of_match = 
	let open SoxmMatch in
    let _ = (* XXX check *)
      if ((checksum) && ((get_dl_header_dl_type bits) = 0x800)) then 
        let ip_data = Cstruct.shift bits sizeof_dl_header in
        let len = (get_nw_header_hlen_version ip_data) land 0xf in 
        let _ = set_nw_header_csum ip_data 0 in
        let csm = Tcpip_checksum.ones_complement (Cstruct.sub ip_data 0 (len*4)) in
        let _ = set_nw_header_csum ip_data csm in
        let _ = 
          match (get_nw_header_nw_proto ip_data) with
          | 6 (* TCP *) -> 
              let src = Ipaddr.V4.of_int32 (get_nw_header_nw_src ip_data) in 
              let dst = Ipaddr.V4.of_int32 (get_nw_header_nw_dst ip_data) in 
              let tp_data = Cstruct.shift ip_data (len*4) in  
              let _ = set_tcpv4_checksum tp_data 0 in
              let csm = tcp_checksum ~src ~dst [tp_data] in 
                set_tcpv4_checksum tp_data csm  
          | 17 (* UDP *) -> ()
          | _ -> ()
        in
          () 
    in 
    match port with
    | PhysicalPort portId -> 
      if Hashtbl.mem st.int_to_port portId then
        let out_p = (!( Hashtbl.find st.int_to_port portId))  in
        send_frame out_p bits 
      else
        return (pp "[switch] forward_frame: Port %ld not registered\n%!" portId)
(*    | OP.Port.No_port -> return () *) (* XXX check *)

    | InPort -> begin
	  match in_port with
	  | Some port ->
		  if Hashtbl.mem st.int_to_port port then
		    send_frame (!(Hashtbl.find st.int_to_port port))  bits
		  else
		    return (pp "[switch] forward_frame: Port %ld unregistered\n%!" port)
	  | None ->
			return (pp "[switch] forward_frame: Input port undefined!") (* XXX return error to the controller? *)
	  end

    | Flood (* XXX TODO VLAN *)
    | AllPorts ->
      Lwt_list.iter_p
        (fun (p : port) -> 
		  match in_port with
		  | Some port ->
			  if (p.port_id != port) then (* all ports except input port *) 
            	send_frame p bits
			  else 
             	return ()
		  | None -> send_frame p bits
        ) st.ports

    | Local ->
      let local = (PseudoPort.marshal Local) in 
      if Hashtbl.mem st.int_to_port local then
        send_frame !(Hashtbl.find st.int_to_port local) bits
      else 
        return (pp "[switch] forward_frame: Port %ld unregistered \n%!" local)

	(* XXX Controller port is removed ... *)
    | Controller c -> begin (* XXX c doesn't exists in manual?! *)
       match st.controller with
       | None -> return ()
       | Some conn -> 
		  match in_port with
		  | Some port ->
			  let pkt_in = ({ pi_payload = NotBuffered bits
							; pi_total_len = Cstruct.len bits
							; pi_reason = ExplicitSend
							; pi_table_id = table
							; pi_cookie = cookie
							; pi_ofp_match =  of_match
							}) 
							in
				OSK.send_packet conn (Message.marshal (Random.int32 Int32.max_int) (PacketInMsg pkt_in)) 
		  | None ->
			  return (pp "[switch] forward_frame: Input port undefined!") (* XXX return error to the controller? *)
       end 
        (*           | Table
         *           | Normal  *)
	| Table (* XXX TODO *)
	| Any (* XXX TODO *)
	| _ -> 
	  return (pp "[switch] forward_frame: unsupported output port\n")

  let set_field field bits checksum =
	(* XXX any check to see if set-field matches packet type? 
	 for isntance, OxmIP4Src has to apply to an IPv4 packet *)
	let open SoxmMatch in
	match field with
    | OxmEthSrc eaddr -> (* XXX mask is ignored. What is the case in manual? *)
      let _ = set_dl_header_dl_src (Int64.to_string eaddr.m_value) 0 bits in 
    	  return checksum
    | OxmEthDst eaddr ->
      let _ = set_dl_header_dl_dst (Int64.to_string eaddr.m_value) 0 bits in 
          return checksum 
  (* TODO: Add for this actions to check when inserted if 
    * the flow is an ip flow *)
    | OxmIPDscp dscp -> (* XXX TODO *)
      let ip_data = Cstruct.shift bits sizeof_dl_header in
      	let _ = set_nw_header_nw_tos ip_data dscp in
          return true 
  (* TODO: wHAT ABOUT ARP?
   * *)
    | OxmIP4Src ip -> 
      let ip_data = Cstruct.shift bits sizeof_dl_header in
      	let _ = set_nw_header_nw_src ip_data ip.m_value in 
          return true 
    | OxmIP4Dst ip -> 
      let ip_data = Cstruct.shift bits sizeof_dl_header in
        let _ = set_nw_header_nw_dst ip_data ip.m_value in 
          return true 
    | OxmTCPSrc port 
	| OxmUDPSrc port ->
      let ip_data = Cstruct.shift bits sizeof_dl_header in
      let len = (get_nw_header_hlen_version ip_data) land 0xf in 
      let tp_data = Cstruct.shift ip_data (len*4) in
      let _ = set_tp_header_tp_src tp_data port in 
        return true 
    | OxmTCPDst port
	| OxmUDPDst port ->
      let ip_data = Cstruct.shift bits sizeof_dl_header in
      let len = (get_nw_header_hlen_version ip_data) land 0xf in 
      let tp_data = Cstruct.shift ip_data (len*4) in 
      let _ = set_tp_header_tp_dst tp_data port in 
        return true
    | act ->
      let _ = (pp "[switch] apply_of_actions: Unsupported set-fields %s" 
                        (Oxm.to_string act)) in (* XXX what happens if action doesn't exist at all? *)
          return checksum
  (*      | OP.Flow.Enqueue(_, _)
          | OP.Flow.Set_vlan_pcp _
          | OP.Flow.Set_vlan_vid _
          | OP.Flow.VENDOR_ACT 
          | OP.Flow.STRIP_VLAN *)

  (* Assume that action are valid. I will not get a flow that sets an ip
   * address unless it defines that the ethType is ip. Need to enforce
   * these rule in the parsing process of the flow_mod packets *)
  let apply_of_actions (st : t') in_port bits (actions : action list)
			table cookie of_match =
	let open SoxmMatch in
    let apply_of_actions_inner (st : t') in_port bits checksum action =
      try_lwt
        match action with
        | Output port ->
          (* Make a packet copy in case the buffer is modified and multiple
           * outputs are defined? *)
          lwt _ = forward_frame st in_port bits checksum port table cookie of_match in 
          return false (* XXX check *)
		| SetField field -> set_field field bits checksum;
		| act ->
     	  	let _ = (pp "[switch] apply_of_actions: Unsupported set-fields %s" 
                       		(Action.to_string act)) in
			return false
      with exn -> 
        let _ = (pp  "[switch] apply_of_actions: (packet size %d) %s %s\n%!" 
                     (Cstruct.len bits) (Action.to_string action) 
                     (Printexc.to_string exn )) in
        return checksum 
    in
    let rec apply_of_actions_rec (st : t') in_port bits checksum = function
      | [] -> return false
      | head :: actions -> 
        lwt checksum = apply_of_actions_inner st in_port bits checksum head in
        apply_of_actions_rec st in_port bits checksum actions 
    in 
    lwt _ = apply_of_actions_rec st in_port bits false actions in 
    return ()


  let lookup_flow (table : Table.t) of_match =
  (* Check first the match table cache
   * NOTE an exact match flow will be found on this step and thus 
   * return a result immediately, without needing to get to the cache table
   * and consider flow priorities *)
	(* let _ = pp "[switch] comparing flow %s\n" (flow_info_to_string of_match) in *)
	if (Hashtbl.mem table.cache of_match) then
       let entry = (Hashtbl.find table.cache of_match) in
     	Found(entry) 
	else begin
     (* Check the wilcard card table *)
	  let lookup_flow flow entry r =
		match (r, SoxmMatch.check_flow_overlap of_match flow) with
		| (_, false) -> r
		| (None, true) -> Some(flow, entry)
		| (Some(f,e), true) when (Entry.(e.counters.priority > entry.counters.priority)) -> r
		| (Some(f,e), true) when (Entry.(e.counters.priority <= entry.counters.priority)) -> 
		   Some(flow, entry)
		| (_, _) -> r
		in
		let flow_match = Hashtbl.fold lookup_flow table.entries None in
		  match (flow_match) with
		  | None ->  NOT_FOUND
		  | Some(f,e) ->
		    Hashtbl.add table.cache of_match (ref e);
		    Entry.(e.match_fields <- of_match :: e.match_fields); 
		  	  Found (ref e)
	end


  let create_tcp_connection tcp (contaddr, contport) =
	T.create_connection tcp (Ipaddr.V4.of_string_exn contaddr, contport)
	>>= function 
		  | `Error e -> fail (Failure "[Swicth] failed connecting to the controller")
		  | `Ok fl -> (return fl)  (* returns flow *)

  let process_frame st (p : port) frame =
	let _ = p.pkt_count <- p.pkt_count + 1 in
      p.in_push (Some frame);
	  return ()

  let init_switch_info ?(verbose=true) dpid = 
	{ (* dev_to_port=(Hashtbl.create 64); *)
	int_to_port = (Hashtbl.create 64); ports = [];
	controller=None;
	last_echo_req=0.; echo_resp_received=true;
	stats= {n_frags=0L; n_hits=0L; n_missed=0L; n_lost=0L;};
	errornum = 0l; portnum=0l;
	table = [Table.init_table ()]; (* XXX we create a single table at the moment *)
	features'=(switch_features dpid); 
	packet_buffer=[]; packet_buffer_id=0l; ready=(Lwt_condition.create ());
	verbose; pkt_len=1500;}

(* add port to the switch *) 
  let add_port ?(use_mac=false) (sw : t') ethif = 

	sw.portnum <- Int32.add sw.portnum 1l;
	let hw_addr =  Macaddr.to_string (E.mac ethif) in
	(* let dev_name = N.id (E.id ethif) in *) (* TODO : how to extract dev_name? *)
	let _ = pp "[switch] Adding port %ld '%s' \n%!" 
								sw.portnum hw_addr in
	let port = init_port sw.portnum ethif in 
	  sw.ports <- sw.ports @ [port]; 
	  Hashtbl.add sw.int_to_port sw.portnum (ref port); 
(*	  sw.features' <- {
		switch_id = sw.features'.switch_id;
		num_buffers = sw.features'.num_buffers;
		num_tables = sw.features'.num_tables; 
		supported_capabilities = sw.features'.supported_capabilities;
		supported_actions = sw.features'.supported_actions;
		ports = sw.features'.ports @ [port.phy'];}; *)
	  let _ = N.listen (E.id ethif) (process_frame sw port) in 
	  match sw.controller with
		| None -> return ()
		| Some t -> OSK.send_packet t 
			(Message.marshal (Random.int32 Int32.max_int) (PortStatusMsg {reason = PortAdd; desc = port.phy}))
  
  let get_flow_stats (table : Table.t) (ptrn : OfpMatch.t) =
	let match_flows ptrn key value ret =
	  if (SoxmMatch.check_flow_overlap key ptrn (* wcard *)) then ( 
	  (Entry.flow_counters_to_flow_stats key (1) value)::ret  (* XXX table id? *)
	  ) else 
        ret 
	in
	  Hashtbl.fold (fun key value r -> match_flows ptrn key value r) 
	  table.Table.entries []  

let process_buffer_id (st : t') t msg xid buffer_id actions = (* XXX important: check functionality *)
  let pkt_in = ref None in

  let _ = 
	st.packet_buffer <- (* Do we need to keep this big list? Also, pkt_in is the last one in the buffer?! *)
      List.filter ( fun a -> 
		match a.pi_payload with
		| NotBuffered p -> true (* XXX what we can do? *)
		| Buffered (n, p) -> 
			if (n = buffer_id) then
    	  		(pkt_in := Some (a); false )
			else true 
			) st.packet_buffer in 
			  match (!pkt_in) with 
				| None ->
					pp "[switch**] invalid buffer id %ld\n%!" buffer_id; 
					OSK.send_packet t (Message.marshal xid (Error {err = BadRequest ReqBufferUnknown; data = msg}))
				| Some (pkt_in) ->
					apply_of_actions st (None (* Some pkt_in.port *)) msg actions
						pkt_in.pi_table_id pkt_in.pi_cookie pkt_in.pi_ofp_match
						(* XXX check: pkt_in.data or msg? *)
	
let process_openflow (st : t') t (xid, msg) =
  let open Message in

  let _ = if st.verbose then pp "[switch*] %s\n%!" (Message.to_string msg) in

  match msg with
	| Hello buf -> return ()
	| EchoRequest buf -> (* Reply to ECHO requests *)
    	OSK.send_packet t (Message.marshal xid msg) 
	| EchoReply buf -> return (st.echo_resp_received <- true) 
	| FeaturesRequest  -> 
    	OSK.send_packet t (Message.marshal xid (FeaturesReply st.features'))

	| MultipartReq {mpr_type = req; mpr_flags = flag } -> begin
		match req with
		  | SwitchDescReq ->
			let p = SwitchDescReply { mfr_desc = "Mirage"
					; hw_desc = "Mirage"
					; sw_desc = "Mirage"
					; serial_num = "0.1" } in
			let rep = {mpreply_typ = p; mpreply_flags = false} in (* XXX check flag *)
 			  OSK.send_packet t (Message.marshal xid (MultipartReply rep)) 

		  | PortsDescReq ->
			let stats = PortsDescReply (List.map (fun x -> x.phy) st.ports) in
			let rep = {mpreply_typ = stats; mpreply_flags = false} in (* XXX check flag *)
 			  OSK.send_packet t (Message.marshal xid (MultipartReply rep)) 
(*		  | FlowStatsReq req ->



type flowRequest = {fr_table_id : tableId; fr_out_port : portId; 
                    fr_out_group : portId; fr_cookie : int64 mask;
                    fr_match : oxmMatch}



type flowStats = { table_id : tableId; duration_sec : int32; duration_nsec : 
                   int32; priority : int16; idle_timeout : timeout; 
                   hard_timeout : timeout; flags : flowModFlags; cookie : int64;
                   packet_count : int64; byte_count : int64; ofp_match : oxmMatch;
                   instructions : instruction list} *)
(*
		  | PortStatsReq port ->
			let stats = PortStatsReply (List.map (fun x -> x.counter) st.ports) in
			let rep = {mpreply_typ = stats; mpreply_flags = false} in (* XXX check flag *)
 			  OSK.send_packet t (Message.marshal xid (MultipartReply rep)) 
*)
(*
		  | AggregFlowStatsReq of flowRequest
		  | TableStatsReq
		  | PortStatsReq of portId
		  | QueueStatsReq of queueRequest
		  | GroupStatsReq of int32
		  | GroupDescReq
		  | GroupFeatReq
		  | MeterStatsReq of int32
		  | MeterConfReq of int32
		  | MeterFeatReq
		  | TableFeatReq of (tableFeatures list) option
		  | ExperimentReq of experimenter  
*)
	end
(*
	| StatsRequestMsg req -> begin
		match req with
		  | DescriptionRequest ->
			let p = DescriptionRep 
						{ manufacturer = "Mirage"
						; hardware = "Mirage"
						; software = "Mirage"
						; serial_number = "0.1"
						; datapath = "Mirage" } in 
 			  OSK.send_packet t (Message.marshal xid (StatsReplyMsg p)) 
	(*	  | FlowTableStatsRequest ->  (* XXX important: no specific reply is defined in frenetic *)
			  let p = IndividualFlowRep [st.table.Table.stats] in 
				OSK.send_packet t (Message.marshal xid (StatsReplyMsg p)) *)
				 
		  | IndividualRequest sreq -> (* (req_h, of_match, table_id, out_port) *)
			  (*TODO Need to consider the  table_id and the out_port and 
			   * split reply over multiple openflow packets if they don't
			   * fit a single packet. *)
			  let flows = get_flow_stats st sreq.is_of_match in (* XXX check the change *)
			(* (* XXX size restriction removed. check *)
			  let stats = OP.Stats.({st_ty=FLOW; more=true;}) in 
			  lwt (_, flows) = 
				Lwt_list.fold_right_s (
				  fun fl (sz, flows) ->
				    let fl_sz = OP.Flow.flow_stats_len fl in 
				      if (sz + fl_sz > 0xffff) then 
				        let r = OP.Stats.Flow_resp(stats, flows) in
				        let h = OP.Header.create ~xid STATS_RESP (OP.Stats.resp_get_len r) in 
				        lwt _ = OSK.send_packet t (OP.Stats_resp (h, r)) in
					        return ((OP.Header.get_len + OP.Stats.get_resp_hdr_size + fl_sz), [fl])
				      else
				        return ((sz + fl_sz), (fl::flows)) )
				  flows ((OP.Header.get_len + OP.Stats.get_resp_hdr_size), []) in *)
(* 
			  let stats = OP.Stats.({st_ty=FLOW; more=false;}) in 
			  let r = OP.Stats.Flow_resp(stats, flows) in
			  let h = OP.Header.create ~xid STATS_RESP (OP.Stats.resp_get_len r) in
			  OSK.send_packet t (OP.Stats_resp (h, r)) *)
			  OSK.send_packet t (Message.marshal xid (StatsReplyMsg (IndividualFlowRep flows)))
			  
		  | AggregateRequest areq -> 
			  let match_flows_aggr of_match key value (fl_b, fl_p, fl) =
				let open Entry in
				if (SMatch.flow_match_compare key of_match) then (* XXX get_flow_stats? *)
				  ((Int64.add fl_b value.counters.n_bytes), (Int64.add fl_p
				  value.counters.n_packets), (Int32.succ fl))
				else (fl_b, fl_p, fl) in 
			  let (byte_count, packet_count,flow_count) = 
				Hashtbl.fold (match_flows_aggr areq.as_of_match) 
					st.table.Table.entries (0L, 0L, 0l) in
					OSK.send_packet t (Message.marshal xid (StatsReplyMsg (AggregateFlowRep 
					  {total_byte_count = byte_count; total_packet_count = packet_count;flow_count;})))
(*
		  | OP.Stats.Port_req(req_h, port) -> begin
			   match port with
			   | OP.Port.No_port -> 
				 let port_stats = List.map (fun p -> p.counter) st.ports in
				 let stats = OP.Stats.({st_ty=PORT; more=false;}) in 
				 let r = OP.Stats.Port_resp(stats, port_stats) in 
				 let h = OP.Header.create ~xid OP.Header.STATS_RESP (OP.Stats.resp_get_len r) in 
				 OSK.send_packet t (OP.Stats_resp (h, r)) 
			   | OP.Port.Port(port_id) -> begin
				   try_lwt 
				    let port = Hashtbl.find st.int_to_port port_id in
				    let stats = OP.Stats.({st_ty=PORT; more=false;}) in 
				    let r = OP.Stats.Port_resp(stats, [(!port).counter]) in 
				    let h = create ~xid STATS_RESP (OP.Stats.resp_get_len r) in 
				    OSK.send_packet t (OP.Stats_resp (h, r))
				   with Not_found ->
				  (* TODO reply with right error code *)
				      pp "[switch] unregistered port %s\n%!"(OP.Port.string_of_port port);
				      let h = create ~xid ERROR (OP.Header.get_len + 4) in 
				      OSK.send_packet t (OP.Error (h, OP.ACTION_BAD_OUT_PORT, (get_new_buffer 0)))
				  end 
			  | _ -> 
          		pp "[switch] unsupported stats request\n%!";
				let h = create ~xid ERROR (get_len + 4) in 
				OSK.send_packet t OP.(Error (h, ACTION_BAD_OUT_PORT, (marshal msg))) 
		  end *)
		  | _ ->
			OSK.send_packet t (Message.marshal xid (ErrorMsg (Error (Error.BadRequest BadSubType, Cstruct.create 0))))
	end 

  | ConfigRequestMsg ->
		OSK.send_packet t (Message.marshal xid (ConfigReplyMsg { frag_flags = FragNormal; miss_send_len = st.pkt_len}))
			(* XXX check it *)

  | BarrierRequest ->
	  OSK.send_packet t (Message.marshal xid (BarrierReply))

  | PacketOutMsg pkt ->
	begin
	  match pkt.output_payload with 
		| NotBuffered p -> apply_of_actions st pkt.port_id p pkt.apply_actions (* pkt.port_id : portId option *)
		| Buffered (n, p) -> process_buffer_id st t p xid n pkt.apply_actions 
	end

  | FlowModMsg fm ->
      lwt _ = 
        match fm.command with
          | AddFlow | ModFlow | ModStrictFlow -> 
            Table.add_flow st st.table fm st.verbose
          | DeleteFlow | DeleteStrictFlow ->
            (* Need to implemente strict deletion in order to enable signpost
             * switching *)
            Table.del_flow st.table fm.pattern fm.out_port (Some t) st.verbose 
	  in
		return ()

  | SetConfig msg -> 
          (* use miss_send_len when sending a pkt_in message*)
          let _ = st.pkt_len <- msg.miss_send_len in
          return ()
(*
  | BarrierReply
  | StatsReplyMsg _
  | PortStatusMsg _
  | FlowRemovedMsg _
  | PacketInMsg _
  | ConfigReplyMsg _
  | SwitchFeaturesReply _
  | VendorMsg _
  | ErrorMsg _ ->
*)
  | _ ->
	  OSK.send_packet t (Message.marshal xid (ErrorMsg (Error (Error.BadRequest BadType, Cstruct.create 0))))
*)
(* end of process_openflow *)

(*************************************************
 * Switch OpenFlow control channel 
 *************************************************)
(*
  let monitor_control_channel (sw : t') conn =
	let is_active = ref true in 
  	while_lwt !is_active do
      let _ = sw.echo_resp_received <- false in 
      let _ = sw.last_echo_req <- (Clock.time ()) in 
      lwt _ = OSK.send_packet conn (Message.marshal 1l (EchoRequest (Cstruct.create 0))) in
		lwt _ = OS.Time.sleep 10.0 in 
		return (is_active := sw.echo_resp_received) 
	done 

  let control_channel_run (st : t') conn = 
	(* Trigger the dance between the 2 nodes *)
	(*let h = OP.Header.(create ~xid:1l HELLO sizeof_ofp_header) in  
	let _ = OSK.send_packet conn (OP.Hello(h)) in *)
	let _ = OSK.send_packet conn (Message.marshal 1l (Hello (Cstruct.create 0))) in

	let rec echo () =
	  try_lwt
		OSK.read_packet conn >>= 
		fun msg -> process_openflow st conn msg >> echo ()
	  with
		| Unparsed (m, bs) ->
		  pp "[switch] ERROR:unparsed! m=%s\n %!" m; echo ()
		| exn ->
		  return (pp "[switch] ERROR:%s\n%!" (Printexc.to_string exn)) (* ; echo () *)
	  in
	  lwt _ = 
		echo () <?> 
		(Table.monitor_flow_timeout st.table (Some conn) st.verbose) <?>
		(monitor_control_channel st conn)
	  in 
	  let _ = OSK.close conn in 
		return (pp "[switch] control channel thread returned")


  (*********************************************
   * Switch OpenFlow data plane 
   *********************************************)

(* in checking progress ... *)
  let process_frame_inner (st : t') (p : port) frame =
  	try_lwt
      let in_port = p.port_id in 
      let tupple = (SMatch.raw_packet_to_match in_port frame)  in 
	  (* Update port rx statistics *)
	  let _ = update_port_rx_stats (Int64.of_int (Cstruct.len frame)) p in

	  (* Lookup packet flow to existing flows in table *)
		match  (lookup_flow st tupple) with 
		  | NOT_FOUND -> begin
			  (* Table.update_table_missed st.table; *) (* XXX check, do we need it? *)
			  let buffer_id = st.packet_buffer_id in
			  (*TODO Move this code in the Switch module *)
			  st.packet_buffer_id <- Int32.add st.packet_buffer_id 1l; (*XXX check what is this *)
			  let pkt_in = ({ input_payload = Buffered (buffer_id, frame)
							; total_len = Cstruct.len frame
							; port = in_port
							; reason = NoMatch
							}) in
			  st.packet_buffer <- pkt_in::st.packet_buffer; 

			  (* Disable for now packet trimming for buffered packets *)
			  let size =
				if (Cstruct.len frame > 92) then 92
				else Cstruct.len frame in
				  let pkt_in = ({ input_payload = Buffered (buffer_id, Cstruct.sub frame 0 size)
							; total_len = Cstruct.len frame
							; port = in_port
							; reason = NoMatch
							}) in				  
					return (
					  match st.controller with
						| None -> pp "[switch] Controller not set."
						| Some conn ->
							  ignore_result 
								(OSK.send_packet conn (Message.marshal (Random.int32 Int32.max_int) (PacketInMsg pkt_in)))
					)
      		end (* switch not found*)
	       (* generate a packet in event *)
		| Found (entry) ->
			let _ = print_endline "entry found..." in
			(* let _ = Table.update_table_found st.table in *)
			let _ = Entry.update_flow (Int64.of_int (Cstruct.len frame)) !entry in
			apply_of_actions st tupple.inPort frame (!entry).Entry.actions
	  
	  with exn ->
		return (pp "[switch] process_frame_inner: control channel error: %s\n" 
        	(Printexc.to_string exn))


  (* Swicth operation *)
  let forward_thread (st : t') =
	Lwt_list.iter_p (fun (p : port) -> 
	  while_lwt true do
        lwt _ = Lwt_stream.next p.in_queue >>= process_frame_inner st p in
        return (p.pkt_count <- p.pkt_count - 1)  (* XXX why packet_count is subtracted by 1? *)
	  done  <&> (
	  while_lwt true do
		lwt frame = Lwt_stream.next p.out_queue in
		E.write p.ethif frame
	  done
	  )
    ) st.ports


  let rec add_switch_ports sw ethlist =
	match ethlist with
	  | [] -> return ()
	  | eth::t -> add_port sw eth >> add_switch_ports sw t

  let create_switch tcp cont ethlist =
		let rec connect_socket () =
		  let sock = ref None in 
			try_lwt
			  let _ = pp "connecting to the remote controller...\n%!" in 
			  	lwt _ = Lwt.pick
				    [create_tcp_connection tcp cont >>= (fun t -> return (sock:= Some t));
				     (OS.Time.sleep 10.0)]
				  in
				  match !sock with
				  | None -> connect_socket ()
				  | Some t -> return t 
			with exn -> connect_socket ()
		in
		  let sw = init_switch_info 0x100L (* model *) in (* XXX move "verbose" and "dpid" to the unikernel *)
		  lwt _ = add_switch_ports sw ethlist in
		  connect_socket ()
			>>= fun fl -> 
				let conn = OSK.init_socket_conn_state (OSK.create fl)
				  in (* up to here, connection in stablished correctly *) 
					let _ = sw.controller <- (Some conn) in 
					lwt _ = ((control_channel_run sw conn) <&> (forward_thread sw) ) in 
		  			let _ = OSK.close conn in 
      				  return (pp "[switch] Disconnected from remote controller.\n")

*)
end (* end of Switch module *)

