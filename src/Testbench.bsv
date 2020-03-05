package Testbench;

    import GetPut :: *;
    import Connectable :: *;
    import Vector :: *;
    import StmtFSM :: *;
    import BRAM :: *;

    // Project Modules
    import BlueLib :: *;
    import BlueAXI :: *;
    import AESMemory :: *;

    function BRAMRequestBE#(Bit#(12), Bit#(FPGA_AXI_DATA_WIDTH), TDiv#(FPGA_AXI_DATA_WIDTH, 8)) makeRequest(Bit#(TDiv#(FPGA_AXI_DATA_WIDTH, 8)) writeen, Bit#(12) addr, Bit#(FPGA_AXI_DATA_WIDTH) data);
return BRAMRequestBE{
writeen: writeen,
responseOnWrite:False,
address: addr,
datain: data
};
endfunction

    (* synthesize *)
    module [Module] mkTestbench();
        AESMemory_IFC mem <- mkAESMemory();

        BRAM1PortBE#(Bit#(12), Bit#(FPGA_AXI_DATA_WIDTH), TDiv#(FPGA_AXI_DATA_WIDTH, 8)) bram <- mkBRAM1ServerBE(defaultValue);

        BlueAXIBRAM#(FPGA_AXI_ADDR_WIDTH, FPGA_AXI_DATA_WIDTH, FPGA_AXI_ID_WIDTH) aximem <- mkBlueAXIBRAM(bram.portA);

        mkConnection(aximem.rd, mem.rd);
        mkConnection(aximem.wr, mem.wr);

        AXI4_Lite_Master_Wr#(CONFIG_ADDR_WIDTH, CONFIG_DATA_WIDTH) writeMaster <- mkAXI4_Lite_Master_Wr(16);
        AXI4_Lite_Master_Rd#(CONFIG_ADDR_WIDTH, CONFIG_DATA_WIDTH) readMaster <- mkAXI4_Lite_Master_Rd(16);

        mkConnection(writeMaster.fab, mem.s_wr);
        mkConnection(readMaster.fab, mem.s_rd);

        Stmt s = {
            seq
                action
                BRAMRequestBE#(Bit#(12), Bit#(FPGA_AXI_DATA_WIDTH), TDiv#(FPGA_AXI_DATA_WIDTH, 8)) req = makeRequest('hFFFF, 'h100, 'hF0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0);
                bram.portA.request.put(req);
                endaction
                action
                BRAMRequestBE#(Bit#(12), Bit#(FPGA_AXI_DATA_WIDTH), TDiv#(FPGA_AXI_DATA_WIDTH, 8)) req = makeRequest('hFFFF, 'h101, 'hF0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0);
                bram.portA.request.put(req);
                endaction
                action
                BRAMRequestBE#(Bit#(12), Bit#(FPGA_AXI_DATA_WIDTH), TDiv#(FPGA_AXI_DATA_WIDTH, 8)) req = makeRequest('hFFFF, 'h102, 'hF0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0);
                bram.portA.request.put(req);
                endaction

                action
                BRAMRequestBE#(Bit#(12), Bit#(FPGA_AXI_DATA_WIDTH), TDiv#(FPGA_AXI_DATA_WIDTH, 8)) req = makeRequest('h0000, 'h000, 0);
                bram.portA.request.put(req);
                endaction
                action
                let r <- bram.portA.response.get;
                printColorTimed(GREEN, $format("Key: %h", r));
                endaction
                action
                BRAMRequestBE#(Bit#(12), Bit#(FPGA_AXI_DATA_WIDTH), TDiv#(FPGA_AXI_DATA_WIDTH, 8)) req = makeRequest('h0000, 'h100, 0);
                bram.portA.request.put(req);
                endaction
                action
                let r <- bram.portA.response.get;
                printColorTimed(GREEN, $format("Source: %h", r));
                endaction
                action
                BRAMRequestBE#(Bit#(12), Bit#(FPGA_AXI_DATA_WIDTH), TDiv#(FPGA_AXI_DATA_WIDTH, 8)) req = makeRequest('h0000, 'h101, 0);
                bram.portA.request.put(req);
                endaction
                action
                let r <- bram.portA.response.get;
                printColorTimed(GREEN, $format("Source: %h", r));
                endaction

                printColorTimed(GREEN, $format("Starting key expand test"));
                axi4_lite_write(writeMaster, 'h20, 0);
                action let r <- axi4_lite_write_response(writeMaster); endaction
                axi4_lite_write(writeMaster, 'h30, 'h0000);
                action let r <- axi4_lite_write_response(writeMaster); endaction
                axi4_lite_write(writeMaster, 'h00, 1);
                action let r <- axi4_lite_write_response(writeMaster); endaction
                await(mem.interrupt());
                axi4_lite_read(readMaster, 'h10);
                action
                    let ret <- axi4_lite_read_response(readMaster);
                    printColorTimed(GREEN, $format("Done with key expand test %d", ret));
                endaction

                printColorTimed(GREEN, $format("Starting encrypt test"));
                axi4_lite_write(writeMaster, 'h20, 1);
                action let r <- axi4_lite_write_response(writeMaster); endaction
                axi4_lite_write(writeMaster, 'h40, 'h1000);
                action let r <- axi4_lite_write_response(writeMaster); endaction
                axi4_lite_write(writeMaster, 'h50, 'h2000);
                action let r <- axi4_lite_write_response(writeMaster); endaction
                axi4_lite_write(writeMaster, 'h60, 4096);
                action let r <- axi4_lite_write_response(writeMaster); endaction
                axi4_lite_write(writeMaster, 'h00, 1);
                action let r <- axi4_lite_write_response(writeMaster); endaction
                await(mem.interrupt());
                axi4_lite_read(readMaster, 'h10);
                action
                    let ret <- axi4_lite_read_response(readMaster);
                    printColorTimed(GREEN, $format("Done with encrypt test %d", ret));
                endaction

                action
                BRAMRequestBE#(Bit#(12), Bit#(FPGA_AXI_DATA_WIDTH), TDiv#(FPGA_AXI_DATA_WIDTH, 8)) req = makeRequest('h0000, 'h200, 0);
                bram.portA.request.put(req);
                endaction
                action
                let r <- bram.portA.response.get;
                printColorTimed(GREEN, $format("Encrypted: %h", r));
                endaction

                printColorTimed(GREEN, $format("Starting decrypt test"));
                axi4_lite_write(writeMaster, 'h20, 2);
                action let r <- axi4_lite_write_response(writeMaster); endaction
                axi4_lite_write(writeMaster, 'h40, 'h2000);
                action let r <- axi4_lite_write_response(writeMaster); endaction
                axi4_lite_write(writeMaster, 'h50, 'h3000);
                action let r <- axi4_lite_write_response(writeMaster); endaction
                axi4_lite_write(writeMaster, 'h60, 4096);
                action let r <- axi4_lite_write_response(writeMaster); endaction
                axi4_lite_write(writeMaster, 'h00, 1);
                action let r <- axi4_lite_write_response(writeMaster); endaction
                await(mem.interrupt());
                axi4_lite_read(readMaster, 'h10);
                action
                    let ret <- axi4_lite_read_response(readMaster);
                    printColorTimed(GREEN, $format("Done with decrypt test %d", ret));
                endaction

                action
                BRAMRequestBE#(Bit#(12), Bit#(FPGA_AXI_DATA_WIDTH), TDiv#(FPGA_AXI_DATA_WIDTH, 8)) req = makeRequest('h0000, 'h300, 0);
                bram.portA.request.put(req);
                endaction
                action
                let r <- bram.portA.response.get;
                printColorTimed(GREEN, $format("Destination: %h", r));
                endaction
                action
                BRAMRequestBE#(Bit#(12), Bit#(FPGA_AXI_DATA_WIDTH), TDiv#(FPGA_AXI_DATA_WIDTH, 8)) req = makeRequest('h0000, 'h301, 0);
                bram.portA.request.put(req);
                endaction
                action
                let r <- bram.portA.response.get;
                printColorTimed(GREEN, $format("Destination: %h", r));
                endaction






            endseq
        };
        mkAutoFSM(s);
    endmodule

endpackage
