package AESMemory;

import FIFO :: *;
import FIFOF :: *;
import SpecialFIFOs :: *;
import GetPut :: *;
import Clocks :: *;
import ClientServer :: *;
import Connectable :: *;
import DefaultValue :: *;
import BUtils :: *;
import DReg :: *;
import Vector :: *;

import AES_Params :: *;
import AES_Defs :: *;
import AES_IFCs :: *;
import AES_Encrypt_Decrypt :: *;

import BlueAXI :: *;
import BlueLib :: *;

typedef 2 AES_CORES;

// Configuration Interface
typedef 12 CONFIG_ADDR_WIDTH;
typedef 64 CONFIG_DATA_WIDTH;

// On FPGA Master
typedef 1 FPGA_AXI_ID_WIDTH;
typedef 64 FPGA_AXI_ADDR_WIDTH;
typedef TMul#(AES_CORES, 128) FPGA_AXI_DATA_WIDTH;
typedef 0 FPGA_AXI_USER_WIDTH;

interface AESMemory_IFC;
    (*prefix="S_AXI"*) interface AXI4_Lite_Slave_Rd_Fab#(CONFIG_ADDR_WIDTH, CONFIG_DATA_WIDTH) s_rd;
    (*prefix="S_AXI"*) interface AXI4_Lite_Slave_Wr_Fab#(CONFIG_ADDR_WIDTH, CONFIG_DATA_WIDTH) s_wr;

    (*prefix="M_AXI"*) interface AXI4_Master_Rd_Fab#(FPGA_AXI_ADDR_WIDTH, FPGA_AXI_DATA_WIDTH, FPGA_AXI_ID_WIDTH, FPGA_AXI_USER_WIDTH) rd;
    (*prefix="M_AXI"*) interface AXI4_Master_Wr_Fab#(FPGA_AXI_ADDR_WIDTH, FPGA_AXI_DATA_WIDTH, FPGA_AXI_ID_WIDTH, FPGA_AXI_USER_WIDTH) wr;

    (* always_ready *) method Bool interrupt();
endinterface

function Bit #(128) fn_reverse_bytes_128b (Bit #(128) x);
   Vector #(16, Bit #(8)) v1 = unpack (x);
   Vector #(16, Bit #(8)) v2 = reverse (v1);
   return pack (v2);
endfunction

module mkAESMemory(AESMemory_IFC);

    Vector#(AES_CORES, AES_Encrypt_Decrypt_IFC) aes_e_d <- replicateM(mkAES_Encrypt_Decrypt);

    Integer reg_start = 'h00;
    Integer reg_ret = 'h10;
    // Commands:
    //   0: 'expand key from source'
    //   1: 'encrypt from source to target'
    //   2: 'decrypt from source to target'
    Integer reg_cmd = 'h20;
    Integer reg_key_addr = 'h30;
    Integer reg_src_addr = 'h40;
    Integer reg_dst_addr = 'h50;
    Integer reg_length = 'h60;

    Reg#(Bool) start <- mkReg(False);
    Reg#(Bool) idle <- mkReg(True);
    Reg#(Bit#(CONFIG_DATA_WIDTH)) status <- mkReg(0);
    Reg#(Bit#(3)) command <- mkReg(0);
    Reg#(Bit#(CONFIG_DATA_WIDTH)) key_addr <- mkReg(0);
    Reg#(Bit#(CONFIG_DATA_WIDTH)) src_addr <- mkReg(0);
    Reg#(Bit#(CONFIG_DATA_WIDTH)) dst_addr <- mkReg(0);
    Reg#(Bit#(CONFIG_DATA_WIDTH)) length <- mkReg(0);

    Wire#(Bool) interrupt_w <- mkDWire(False);

    List#(RegisterOperator#(axiAddrWidth, CONFIG_DATA_WIDTH)) operators = Nil;
    operators = registerHandler(reg_start, start, operators);
    operators = registerHandler(reg_ret, status, operators);
    operators = registerHandler(reg_cmd, command, operators);
    operators = registerHandler(reg_key_addr, key_addr, operators);
    operators = registerHandler(reg_src_addr, src_addr, operators);
    operators = registerHandler(reg_dst_addr, dst_addr, operators);
    operators = registerHandler(reg_length, length, operators);
    GenericAxi4LiteSlave#(CONFIG_ADDR_WIDTH, CONFIG_DATA_WIDTH) s_config <- mkGenericAxi4LiteSlave(operators, 1, 1);

    Axi4MasterRead#(FPGA_AXI_ADDR_WIDTH, FPGA_AXI_DATA_WIDTH, FPGA_AXI_ID_WIDTH, FPGA_AXI_USER_WIDTH, 32) rdMaster <- mkAxi4MasterRead(2, 2, True, 256, True, 2, True);
    Axi4MasterWrite#(FPGA_AXI_ADDR_WIDTH, FPGA_AXI_DATA_WIDTH, FPGA_AXI_ID_WIDTH, FPGA_AXI_USER_WIDTH, 32) wrMaster <- mkAxi4MasterWrite(2, 2, True, 256, True, 2, True);

    Reg#(UInt#(CONFIG_DATA_WIDTH)) cycleCount <- mkRegU;

    Reg#(Bool) lastCycle <- mkReg(False);

    Reg#(Bool) finish <- mkRegU;

    Reg#(Bool) keyRead <- mkReg(False);

    Reg#(Bit#(CONFIG_DATA_WIDTH)) outstanding <- mkRegU;

    Reg#(Bool) interruptR <- mkDReg(False);

    rule readKey if(idle && start && command == 0);
        rdMaster.server.request.put(AxiRequest {address: key_addr, bytesToTransfer: 16, region: 0});
        start <= False;
        idle <= False;
        cycleCount <= 0;
        keyRead <= False;
    endrule

    rule acceptKey if(!keyRead && command == 0);
        let key <- rdMaster.server.response.get();
        let key_reversed = fn_reverse_bytes_128b(key[127:0]);
        for (Integer i = 0; i < valueOf(AES_CORES); i = i + 1)
            aes_e_d[i].set_key(key_reversed);
        keyRead <= True;
        idle <= True;
        status <= pack(cycleCount);
        interruptR <= True;
    endrule

    rule startOp if(idle && start && command != 0 && keyRead);
        start <= False;
        idle <= False;
        cycleCount <= 0;
        outstanding <= length;
        rdMaster.server.request.put(AxiRequest {address: src_addr, bytesToTransfer: cExtend(length), region: 0});
        wrMaster.request.put(AxiRequest {address: dst_addr, bytesToTransfer: cExtend(length), region: 0});
        finish <= False;
    endrule

    rule encryptData if(!idle && keyRead && command == 1);
        let data <- rdMaster.server.response.get();
        for (Integer i = 0; i < valueOf(AES_CORES); i = i + 1)
            aes_e_d[i].encrypt.request.put(fn_reverse_bytes_128b(data[((i+1) * 128) - 1:i * 128]));
    endrule

    rule decryptData if(!idle && keyRead && command == 2);
        let data <- rdMaster.server.response.get();
        for (Integer i = 0; i < valueOf(AES_CORES); i = i + 1)
            aes_e_d[i].decrypt.request.put(fn_reverse_bytes_128b(data[((i+1) * 128) - 1:i * 128]));
    endrule

    rule writeEncrypted if(!idle && command == 1);
        Bit#(128) data0 <- aes_e_d[0].encrypt.response.get;
        Bit#(128) data1 <- aes_e_d[1].encrypt.response.get;
        Bit#(128) data2 <- aes_e_d[2].encrypt.response.get;
        Bit#(128) data3 <- aes_e_d[3].encrypt.response.get;
        Bit#(FPGA_AXI_DATA_WIDTH) data = {fn_reverse_bytes_128b(data3), fn_reverse_bytes_128b(data2), fn_reverse_bytes_128b(data1), fn_reverse_bytes_128b(data0)};
        wrMaster.data.put(data);
        let outstanding_next = outstanding - (16 * fromInteger(valueOf(AES_CORES)));
        if (outstanding_next <= 0) finish <= True;
        outstanding <= outstanding_next;
    endrule

    rule writeDecrypted if(!idle && command == 2);
        Bit#(128) data0 <- aes_e_d[0].decrypt.response.get;
        Bit#(128) data1 <- aes_e_d[1].decrypt.response.get;
        Bit#(128) data2 <- aes_e_d[2].decrypt.response.get;
        Bit#(128) data3 <- aes_e_d[3].decrypt.response.get;
        Bit#(FPGA_AXI_DATA_WIDTH) data = {fn_reverse_bytes_128b(data3), fn_reverse_bytes_128b(data2), fn_reverse_bytes_128b(data1), fn_reverse_bytes_128b(data0)};
        wrMaster.data.put(data);
        let outstanding_next = outstanding - (16 * fromInteger(valueOf(AES_CORES)));
        if (outstanding_next <= 0) finish <= True;
        outstanding <= outstanding_next;
    endrule

    rule count if(!start);
        cycleCount <= cycleCount + 1;
        lastCycle <= wrMaster.active;
        if (lastCycle && !wrMaster.active && finish) begin
            idle <= True;
            status <= pack(cycleCount);
            interruptR <= True;
        end
    endrule

    interface s_rd = s_config.s_rd;
    interface s_wr = s_config.s_wr;

    interface rd = rdMaster.fab;
    interface wr = wrMaster.fab;

    method Bool interrupt = interruptR;
endmodule

endpackage
