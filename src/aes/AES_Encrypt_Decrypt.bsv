// Copyright (c) 2015-2017 Bluespec, Inc.  All Rights Reserved
// Author: Rishiyur S. Nikhil (Bluespec, Inc.)

// ================================================================
// This code implements the core functions of the AES algorithm:
//     key expansion of a 128b key
//     encryption of a 128b block using that key
//     decryption of a 128b block using that key
// The AES 'rounds' are done sequentially, with each round
// transforming a single 'state' register.

// Spec for this code: AES.cry in Cryptol distribution.
// cf. "Programming Cryptol", book from Galois, Inc. (galois.com)
// Book and Cryptol distribution containing AES.cry downloaded from:
//     http://cryptol.net

// ================================================================

package AES_Encrypt_Decrypt;

// ================================================================
// imports from BSV lib

import Vector        :: *;
import FIFOF         :: *;
import StmtFSM       :: *;
import GetPut        :: *;
import ClientServer  :: *;

// ----------------------------------------------------------------
// imports for this project

import AES_Params     :: *;
import AES_Defs       :: *;
import AES_KeyExpand  :: *;
import AES_IFCs       :: *;

// ================================================================
// The encryption module

// Number of states
typedef TAdd#(2,Nr) Ns;
Integer ns = valueOf(Ns);

(* synthesize *)
module mkAES_Encrypt_Decrypt (AES_Encrypt_Decrypt_IFC);

   // Key-expansion sub-module

   AES_KeyExpand_IFC keyExpand <- mkAES_KeyExpand;

   match { .ekInit,  .eks, .ekFinal } = keyExpand.keySchedule;
   match { .dkFinal, .dks, .dkInit  } = keyExpand.keySchedule;

   // AES Round state

   Vector#(Ns, FIFOF#(State)) enc_states <- replicateM(mkFIFOF);
   Vector#(Ns, FIFOF#(State)) dec_states <- replicateM(mkFIFOF);

   // ----------------------------------------------------------------
   // BEHAVIOR

   rule encryptInit;
      let newVal = addRoundKey(ekInit, enc_states[0].first); enc_states[0].deq;
      enc_states[1].enq(newVal);
   endrule

   for (Integer j = 1; j < nr; j = j + 1) begin
      rule encryptRound;
         let newVal = aesRound(eks[j - 1], enc_states[j].first); enc_states[j].deq;
         enc_states[j+1].enq(newVal);
      endrule
   end

   rule encryptFinal;
      let newVal = aesFinalRound(ekFinal, enc_states[nr].first); enc_states[nr].deq;
      enc_states[nr+1].enq(newVal);
   endrule

   rule decryptInit;
      let newVal = addRoundKey(dkInit, dec_states[0].first); dec_states[0].deq;
      dec_states[1].enq(newVal);
   endrule

   for (Integer j = 1; j < nr; j = j + 1) begin
      rule decryptRound;
         let newVal = aesInvRound(reverse(dks)[j - 1], dec_states[j].first); dec_states[j].deq;
         dec_states[j+1].enq(newVal);
      endrule
   end

   rule decryptFinal;
      let newVal = aesFinalInvRound(dkFinal, dec_states[nr].first); dec_states[nr].deq;
      dec_states[nr+1].enq(newVal);
   endrule

   // ----------------------------------------------------------------
   // INTERFACE

   // Supply the key here.
   // This will kick off an internal process to expand the key into
   // the full key schedule.
   method Action set_key (Bit #(AESKeySize) key);
      keyExpand.set_key (key);
   endmethod

   // Indicator that key expansion is complete.
   // This is provided as a convenience, if needed (the 'request'
   // sub-interface in the Server below will not accept inputs until
   // key-expansion is complete).
   method Bool key_ready;
      return keyExpand.key_ready;
   endmethod

   // Encryption: put plaintext and get ciphertext here
   interface Server encrypt;
      interface Put request;
	 method Action put (Bit #(128) plaintext) if (keyExpand.key_ready);
	    enc_states[0].enq(msgToState (plaintext));
	 endmethod
      endinterface
      interface Get response;
	 method ActionValue #(Bit #(128)) get () if (keyExpand.key_ready);
	    let ciphertext = stateToMsg (enc_states[nr+1].first); enc_states[nr+1].deq;
	    return ciphertext;
	 endmethod
      endinterface
   endinterface

   // Decryption: put ciphertext and get plaintext here
   interface Server decrypt;
      interface Put request;
	 method Action put (Bit #(128) ciphertext) if (keyExpand.key_ready);
	    dec_states[0].enq(msgToState (ciphertext));
	 endmethod
      endinterface
      interface Get response;
	 method ActionValue #(Bit #(128)) get () if (keyExpand.key_ready);
	    let plaintext = stateToMsg (dec_states[nr+1].first); dec_states[nr+1].deq;
	    return plaintext;
	 endmethod
      endinterface
   endinterface

endmodule

// ================================================================

endpackage
