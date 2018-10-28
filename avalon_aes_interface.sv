/************************************************************************
Avalon-MM Interface for AES Decryption IP Core

Dong Kai Wang, Fall 2017

For use with ECE 385 Experiment 9
University of Illinois ECE Department

Register Map:

 0-3 : 4x 32bit AES Key
 4-7 : 4x 32bit AES Encrypted Message
 8-11: 4x 32bit AES Decrypted Message
   12: Not Used
	13: Not Used
   14: 32bit Start Register
   15: 32bit Done Register

************************************************************************/

module avalon_aes_interface (
	// Avalon Clock Input
	input logic CLK,
	
	// Avalon Reset Input
	input logic RESET,
	
	// Avalon-MM Slave Signals
	input  logic AVL_READ,					// Avalon-MM Read
	input  logic AVL_WRITE,					// Avalon-MM Write
	input  logic AVL_CS,						// Avalon-MM Chip Select
	input  logic [3:0] AVL_BYTE_EN,		// Avalon-MM Byte Enable
	input  logic [3:0] AVL_ADDR,			// Avalon-MM Address
	input  logic [31:0] AVL_WRITEDATA,	// Avalon-MM Write Data
	output logic [31:0] AVL_READDATA,	// Avalon-MM Read Data
	
	// Exported Conduit
	output logic [31:0] EXPORT_DATA		// Exported Conduit Signal to LEDs
);

logic [31:0] in,out;

reg_file AES_REG_FILE(.Clk(CLK),.Reset(RESET),.LD_REG(AVL_CS && AVL_WRITE),.ADDR(AVL_ADDR),
							 .INPUT(in),.out_en_first(EXPORT_DATA[31:16]),.out_en_last(EXPORT_DATA[15:0]),.OUTPUT(out));
 
always_ff @ (posedge CLK)
begin
    if(RESET)
    begin
			AVL_READDATA <= {32{1'b0}};
			in <= {32{1'b0}};
    end
	 
    else
    begin
	 
		if(AVL_CS && AVL_READ)
		begin
			AVL_READDATA <= out;
		end
		
		else if(AVL_CS && AVL_WRITE)
		begin
			case(AVL_BYTE_EN)
				4'b1111: in <= AVL_WRITEDATA;
				4'b1100: in <= {AVL_WRITEDATA[31:16],16'hz};
				4'b0011: in <= {16'hz,AVL_WRITEDATA[15:0]};
				4'b1000: in <= {AVL_WRITEDATA[31:24],24'hz};
				4'b0100: in <= {8'hz,AVL_WRITEDATA[23:16],16'hz};
				4'b0010: in <= {16'hz,AVL_WRITEDATA[15:8],8'hz};
				4'b0001: in <= {24'hz,AVL_WRITEDATA[7:0]};
				default: in <= 32'hz;
			endcase
		end
		
		else
		begin
			AVL_READDATA <= {32{1'b0}};
		end
		
    end
end

endmodule
