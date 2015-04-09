open Packet
open OpenFlow0x01_Core

(** Both [IndividualRequest] and [AggregateRequest] take as paramters,
    a [pattern] that specifies the fields to match, the [table_id]
    to read from, and an optional port, which requires matching
    entries to have this as an output port.  Use table ID [0xFF] to
    read from all tables. *)

(** The body of an individual or aggregate flow stat request. *)
type statsReq =
  { sr_of_match : pattern
  ; sr_table_id : int8
  ; sr_out_port : pseudoPort option
  }

type request =
  | DescriptionRequest
  | FlowTableStatsRequest
  | IndividualRequest of statsReq
  | AggregateRequest of statsReq

  (** The body of a reply to a description request. *)
type descriptionStats =
    { manufacturer : string (** Manufacturer description. *)
    ; hardware : string (** Hardware description. *)
    ; software : string (** Software description. *)
    ; serial_number : string (** Serial number. *)
    ; datapath : string (** Human readable description of datapath. *)
    }
      
  (** The body of a reply to an individual flow statistics request. *)
type individualStats =
    { table_id : int8 (** ID of table flow came from. *)
    ; of_match : pattern (** Description of fields. *)
    ; duration_sec : int32 (** Time flow has been alive in seconds. *)
    ; duration_nsec : int32 (** Time flow has been alive in nanoseconds 
                                beyond [duration_sec]. *)
    ; priority : int16 (** Priority of the entry.  Only meaningful when this
                           is not an exact-match entry. *)
    ; idle_timeout : int16 (** Number of seconds idle before expiration. *)
    ; hard_timeout : int16 (** Number of seconds before expiration. *)
    ; cookie : int64 (** Opaque controller-issued identifier. *)
    ; packet_count : int64 (** Number of packets in flow. *)
    ; byte_count : int64 (** Number of bytes in flow. *)
    ; actions : action list (** Actions. *)
    }

type aggregateStats =
    { total_packet_count : int64 (** Number of packets in flows. *)
    ; total_byte_count : int64 (** Number of bytes in flows. *)
    ; flow_count : int32 (** Number of flows. *)
    }

  (** A statistics reply message.  See Section 5.3.5 of the OpenFlow 1.0 
      specification. *)

type reply =
  | DescriptionRep of descriptionStats
  | IndividualFlowRep of individualStats list
  | AggregateFlowRep of aggregateStats

val reply_to_string : reply -> string
