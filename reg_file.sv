module reg_file
(
	input logic Clk, Reset, LD_REG,
	input logic [3:0] ADDR,
	input logic [32:0] INPUT,
	output logic[16:0] out_en_first, out_en_last,
	output logic [32:0] OUTPUT
);
	
	logic LD_REG0, LD_REG1, LD_REG2, LD_REG3, LD_REG4, LD_REG5, LD_REG6, LD_REG7, 
			LD_REG8, LD_REG9, LD_REG10, LD_REG11, LD_REG12, LD_REG13, LD_REG14, LD_REG15;
	logic [32:0] reg0, reg1, reg2, reg3, reg4, reg5, reg6, reg7, reg8, reg9, reg10, reg11, reg12, reg13, reg14, reg15;

	register32 AES_KEY0(.Clk(Clk),.Reset(Reset),.Load(LD_REG0),.D(INPUT),.Data_Out(reg0));
	register32 AES_KEY1(.Clk(Clk),.Reset(Reset),.Load(LD_REG1),.D(INPUT),.Data_Out(reg1));
	register32 AES_KEY2(.Clk(Clk),.Reset(Reset),.Load(LD_REG2),.D(INPUT),.Data_Out(reg2));
	register32 AES_KEY3(.Clk(Clk),.Reset(Reset),.Load(LD_REG3),.D(INPUT),.Data_Out(reg3));
	register32 AES_MSG_EN0(.Clk(Clk),.Reset(Reset),.Load(LD_REG4),.D(INPUT),.Data_Out(reg4));
	register32 AES_MSG_EN1(.Clk(Clk),.Reset(Reset),.Load(LD_REG5),.D(INPUT),.Data_Out(reg5));
	register32 AES_MSG_EN2(.Clk(Clk),.Reset(Reset),.Load(LD_REG6),.D(INPUT),.Data_Out(reg6));
	register32 AES_MSG_EN3(.Clk(Clk),.Reset(Reset),.Load(LD_REG7),.D(INPUT),.Data_Out(reg7));
	register32 AES_MSG_DE0(.Clk(Clk),.Reset(Reset),.Load(LD_REG8),.D(INPUT),.Data_Out(reg8));
	register32 AES_MSG_DE1(.Clk(Clk),.Reset(Reset),.Load(LD_REG9),.D(INPUT),.Data_Out(reg9));
	register32 AES_MSG_DE2(.Clk(Clk),.Reset(Reset),.Load(LD_REG10),.D(INPUT),.Data_Out(reg10));
	register32 AES_MSG_DE3(.Clk(Clk),.Reset(Reset),.Load(LD_REG11),.D(INPUT),.Data_Out(reg11));
	register32 UNNAMED0(.Clk(Clk),.Reset(Reset),.Load(LD_REG12),.D(INPUT),.Data_Out(reg12));
	register32 UNNAMED1(.Clk(Clk),.Reset(Reset),.Load(LD_REG13),.D(INPUT),.Data_Out(reg13));
	register32 AES_START(.Clk(Clk),.Reset(Reset),.Load(LD_REG14),.D(INPUT),.Data_Out(reg14));
	register32 AES_DONE(.Clk(Clk),.Reset(Reset),.Load(LD_REG15),.D(INPUT),.Data_Out(reg15));
	
	mux16 OUTPUT_SELECT(.d0(reg0),.d1(reg1),.d2(reg2),.d3(reg3),.d4(reg4),.d5(reg5),.d6(reg6),.d7(reg7),.d8(reg8),.d9(reg9),
							  .d10(reg10),.d11(reg11),.d12(reg12),.d13(reg13),.d14(reg14),.d15(reg15),.s(ADDR),.y(OUTPUT))
	
	assign out_en_first = reg4[31:16];
	assign out_en_last = reg7[15:0];
	
	always_comb
	begin
		LD_REG0 = 1'b0;
		LD_REG1 = 1'b0;
		LD_REG2 = 1'b0;
		LD_REG3 = 1'b0;
		LD_REG4 = 1'b0;
		LD_REG5 = 1'b0;
		LD_REG6 = 1'b0;
		LD_REG7 = 1'b0;
		LD_REG8 = 1'b0;
		LD_REG9 = 1'b0;
		LD_REG10 = 1'b0;
		LD_REG11 = 1'b0;
		LD_REG12 = 1'b0;
		LD_REG13 = 1'b0;
		LD_REG14 = 1'b0;
		LD_REG15 = 1'b0;
		
		if(LD_REG)
		begin
			case (ADDR)
				4'b0000: LD_REG0 = 1'b1;
				4'b0001: LD_REG1 = 1'b1;
				4'b0010: LD_REG2 = 1'b1;
				4'b0011: LD_REG3 = 1'b1;
				4'b0100: LD_REG4 = 1'b1;
				4'b0101: LD_REG5 = 1'b1;
				4'b0110: LD_REG6 = 1'b1;
				4'b0111: LD_REG7 = 1'b1;
				4'b1000: LD_REG8 = 1'b1;
				4'b1001: LD_REG9 = 1'b1;
				4'b1010: LD_REG10 = 1'b1;
				4'b1011: LD_REG11 = 1'b1;
				4'b1100: LD_REG12 = 1'b1;
				4'b1101: LD_REG13 = 1'b1;
				4'b1110: LD_REG14 = 1'b1;
				4'b1111: LD_REG15 = 1'b1;
			endcase
		end
   end

endmodule
