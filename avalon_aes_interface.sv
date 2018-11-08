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

logic [31:0] reg_file [0:15];
 
always_ff @ (posedge CLK)
begin

    if(RESET)
    begin
			reg_file[0] <= {32{1'b0}};
			reg_file[1] <= {32{1'b0}};
			reg_file[2] <= {32{1'b0}};
			reg_file[3] <= {32{1'b0}};
			reg_file[4] <= {32{1'b0}};
			reg_file[5] <= {32{1'b0}};
			reg_file[6] <= {32{1'b0}};
			reg_file[7] <= {32{1'b0}};
			reg_file[8] <= {32{1'b0}};
			reg_file[9] <= {32{1'b0}};
			reg_file[10] <= {32{1'b0}};
			reg_file[11] <= {32{1'b0}};
			reg_file[12] <= {32{1'b0}};
			reg_file[13] <= {32{1'b0}};
			reg_file[14] <= {32{1'b0}};
			reg_file[15] <= {32{1'b0}};
    end
	 
   else
    begin
		
		if(AVL_CS && AVL_WRITE)
		begin
			case(AVL_BYTE_EN)
				4'b1111: reg_file[AVL_ADDR] <= AVL_WRITEDATA;
				4'b1100: reg_file[AVL_ADDR][31:16] <= AVL_WRITEDATA[31:16];
				4'b0011: reg_file[AVL_ADDR][15:0] <= AVL_WRITEDATA[15:0];
				4'b1000: reg_file[AVL_ADDR][31:24] <= AVL_WRITEDATA[31:24];
				4'b0100: reg_file[AVL_ADDR][23:16] <= AVL_WRITEDATA[23:16];
				4'b0010: reg_file[AVL_ADDR][15:8] <= AVL_WRITEDATA[15:8];
				4'b0001: reg_file[AVL_ADDR][7:0] <= AVL_WRITEDATA[7:0];
				default: ;
			endcase
		end
    end
end

assign EXPORT_DATA[31:16] = reg_file[4][31:16];
assign EXPORT_DATA[15:0] = reg_file[7][15:0];
assign AVL_READDATA = (AVL_CS && AVL_READ) ? reg_file[AVL_ADDR] : {32{1'b0}};

endmodule
