open V1_LWT
open Lwt
open Printf

open Ofswitch0x04
open Ofsocket0x04

let red fmt    = Printf.sprintf ("\027[31m"^^fmt^^"\027[m")
let green fmt  = Printf.sprintf ("\027[32m"^^fmt^^"\027[m")
let yellow fmt = Printf.sprintf ("\027[33m"^^fmt^^"\027[m")
let blue fmt   = Printf.sprintf ("\027[36m"^^fmt^^"\027[m")

let contaddr= "127.0.0.1"
let contport = 6633

module Main (C: CONSOLE)(S: STACKV4)(N0: NETWORK)(N1: NETWORK)(N2: NETWORK) = struct


  let or_error c name fn t =
    fn t
    >>= function
    | `Error e -> fail (Failure ("error starting " ^ name))
    | `Ok t -> C.log_s c (green "%s connected..." name) >>
               return t

  module T = S.TCPV4
  module E = Ethif.Make(N1)
  module Sw = Ofswitch0x04.Make(T)(N1)

  let start console s n0 n1 n2 =

  let dpid = 
  (* based on 1.4.0 - 7.3 *)
    let rec find_int_mac imac ind =
      match ind with
      | 6 -> imac
      | i -> let chr = Int64.of_int (int_of_char (Macaddr.to_bytes (N0.mac n0)).[i]) in
             let cmb = Int64.logor (Int64.shift_left imac 8) chr in
             find_int_mac cmb (i + 1)
   in
     let imac = find_int_mac Int64.zero 0 in
     (* TODO: possible use of VLAN ID *)
     let rnd = Int64.shift_left (Random.int64 0xffffL) (6 * 8) in
     Int64.logor imac rnd
  in
  let netl = [n1; n2] in
    (* mirage main module <= 1.2.0 doesn't accept list as the parameter.
       write input network devices as a list until mirage supprts list parameters *)
  let rec connect_ifs nl acc =
    match nl with
    | [] -> return acc
    | n::t -> or_error console "ethernet interface" E.connect n >>= fun x -> (connect_ifs t (x::acc))
        (* to do: ethernet interface -> name of the interface: tap1, tap2, ... *)
  in
    C.log_s console 
      (sprintf "IP address: %s\n"
        (String.concat ", " (List.map Ipaddr.V4.to_string (S.IPV4.get_ip (S.ipv4 s)))))
    >> connect_ifs netl []
    >>= fun e ->
        Sw.create_switch (S.tcpv4 s) (contaddr, contport) e dpid

end
