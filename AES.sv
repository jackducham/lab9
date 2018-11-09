/************************************************************************
AES Decryption Core Logic

Dong Kai Wang, Fall 2017

For use with ECE 385 Experiment 9
University of Illinois ECE Department
************************************************************************/

module AES (
	input	 logic CLK,
	input  logic RESET,
	input  logic AES_START,
	output logic AES_DONE,
	input  logic [127:0] AES_KEY,
	input  logic [127:0] AES_MSG_ENC,
	output logic [127:0] AES_MSG_DEC
);
	logic [7:0] isb, osb;
	logic [31:0] imc, omc;
	logic [127:0] key, msg, invSRin, invSRout;
	logic [1407:0] key_schedule;
	
	enum logic [5:0] {WAIT,s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15,s16,s17,s18,s19,s20,s21,s22,s23,s24,s25,
							s26,s27,s28,s29,s30,s31,s32,s33,s34,s35,s36,s37,s38,s39,s40,DONE}, curr_state, next_state;

	assign invSRin = {128{1'b0}};
	assign key = {128{1'b0}};
	assign msg = {128{1'b0}};
	assign isb = {8{1'b0}};
	assign imc = {32{1'b0}};
							
	KeyExpansion keys(.clk(CLK),.Cipherkey(AES_KEY),.KeySchedule(key_schedule));					
	InvShiftRows invshiftrows(.data_in(invSRin),.data_out(invSRout));
	InvSubBytes  invsubbytes(.clk(CLK),.in(isb),.out(osb));
	InvMixColumns invmixcols(.in(imc),.out(omc))
	
always_ff @ (posedge CLK)  
begin
	if (RESET)
		curr_state <= s0;
   else 
		curr_state <= next_state;
end
	 
always_comb
begin
	next_state  = curr_state;	
   unique case (curr_state) 
		WAIT : if(AES_START)
				next_state = s0;
		s0 : next_state = s1;
		s1 : next_state = s2;
		s2 : next_state = s3;
		s3 : next_state = s4;
		s4 : next_state = s5;
		s5 : next_state = s6;
		s6 : next_state = s7;
		s7 : next_state = s8;
      s8 : next_state = s9;
		s9 : next_state = s10;
		s10 : next_state = s11;
		s11 : next_state = s12;
		s12 : next_state = s13;
		s13 : next_state = s14;
		s14 : next_state = s15;
		s15 : next_state = s16;
		s16 : next_state = s17;
		s17 : next_state = s18;
		s18 : next_state = s19;
		s19 : next_state = s20;
		s20 : next_state = s21;
		s21 : next_state = s22;
		s22 : next_state = s23;
		s23 : next_state = s24;
		s24 : next_state = s25;
		s25 : next_state = s26;
		s26 : next_state = s27;
		s27 : next_state = s28;
		s28 : next_state = s29;
		s29 : next_state = s30;
		s30 : next_state = s31;
		s31 : next_state = s32;
		s32 : next_state = s33;
		s33 : next_state = s34;
		s34 : next_state = s35;
		s35 : next_state = s36;
		s36 : next_state = s37;
		s37 : next_state = s38;
		s38 : next_state = s39;
		s39 : next_state = s40;
		s40 : next_state = DONE;
		DONE : if(!AES_START)
				next_state = WAIT;
	endcase
   
        case (curr_state) 
            WAIT: 
				begin
					AES_DONE = 1'b0;
            end
            s0: 
            begin
					key = key_schedule[1407:1280];
					msg = AES_MSG_ENC ^ key;
            end
				s1:
            begin
					invSRin = msg;
					msg = invSRout;
				end
				s2:
				begin
					isb = msg[7:0];
					msg[7:0] = osb;
				end
				s3:
				begin
					isb = msg[15:8];
					msg[15:8 = osb;
				end
				s4:
				begin
					isb = msg[23:16];
					msg[23:16] = osb;
				end
				s5:
				begin
					isb = msg[31:24];
					msg[31:24] = osb;
				end
				s6:
				begin
					isb = msg[39:32];
					msg[39:32] = osb;
				end
				s7:
				begin
					isb = msg[47:40];
					msg[47:40] = osb;
				end
				s8:
				begin
					isb = msg[55:48];
					msg[55:48] = osb;
				end
				s9:
				begin
					isb = msg[63:56];
					msg[63:56] = osb;
				end
				s10:
				begin
					isb = msg[71:64];
					msg[71:64] = osb;
				end
				s11:
				begin
					isb = msg[79:72];
					msg[79:72] = osb;
				end
				s12:
				begin
					isb = msg[87:80];
					msg[87:80] = osb;
				end
				s13:
				begin
					isb = msg[95:88];
					msg[95:88] = osb;
				end
				s14:
				begin
					isb = msg[103:96];
					msg[103:96] = osb;
				end
				s15:
				begin
					isb = msg[111:104];
					msg[111:104] = osb;
				end
				s16:
				begin
					isb = msg[119:112];
					msg[119:112] = osb;
				end
				s17:
				begin
					isb = msg[127:120];
					msg[127:120] = osb;
				end
				s18: 
            begin
					key = key_schedule[1279:1152];
					msg = msg ^ key;
            end
				s19:
				begin
					imc = msg[31:0];
					msg[31:0] = omc;
				end
				s20:
				begin
					imc = msg[63:32];
					msg[63:32] = omc;
				end
				s21: 
            begin
					imc = msg[95:64];
					msg[95:64] = omc;
            end
				s22:
				begin
					imc = msg[127:96];
					msg[127:96] = omc;
				end
				s23:
            begin
					invSRin = msg;
					msg = invSRout;
				end
				s24:
				begin
					isb = msg[7:0];
					msg[7:0] = osb;
				end
				s24:
				begin
					isb = msg[15:8];
					msg[15:8 = osb;
				end
				s26:
				begin
					isb = msg[23:16];
					msg[23:16] = osb;
				end
				s27:
				begin
					isb = msg[31:24];
					msg[31:24] = osb;
				end
				s28:
				begin
					isb = msg[39:32];
					msg[39:32] = osb;
				end
				s29:
				begin
					isb = msg[47:40];
					msg[47:40] = osb;
				end
				s30:
				begin
					isb = msg[55:48];
					msg[55:48] = osb;
				end
				s31:
				begin
					isb = msg[63:56];
					msg[63:56] = osb;
				end
				s32:
				begin
					isb = msg[71:64];
					msg[71:64] = osb;
				end
				s33:
				begin
					isb = msg[79:72];
					msg[79:72] = osb;
				end
				s34:
				begin
					isb = msg[87:80];
					msg[87:80] = osb;
				end
				s35:
				begin
					isb = msg[95:88];
					msg[95:88] = osb;
				end
				s36:
				begin
					isb = msg[103:96];
					msg[103:96] = osb;
				end
				s37:
				begin
					isb = msg[111:104];
					msg[111:104] = osb;
				end
				s38:
				begin
					isb = msg[119:112];
					msg[119:112] = osb;
				end
				s39:
				begin
					isb = msg[127:120];
					msg[127:120] = osb;
				end
				s40: 
            begin
					key = key_schedule[1151:1024];
					msg = msg ^ key;
            end
				s41:
				begin
					imc = msg[31:0];
					msg[31:0] = omc;
				end
				s42:
				begin
					imc = msg[63:32];
					msg[63:32] = omc;
				end
				s43: 
            begin
					imc = msg[95:64];
					msg[95:64] = omc;
            end
				s44:
				begin
					imc = msg[127:96];
					msg[127:96] = omc;
				end
				s45:
            begin
					invSRin = msg;
					msg = invSRout;
				end
				s46:
				begin
					isb = msg[7:0];
					msg[7:0] = osb;
				end
				s47:
				begin
					isb = msg[15:8];
					msg[15:8 = osb;
				end
				s48:
				begin
					isb = msg[23:16];
					msg[23:16] = osb;
				end
				s49:
				begin
					isb = msg[31:24];
					msg[31:24] = osb;
				end
				s50:
				begin
					isb = msg[39:32];
					msg[39:32] = osb;
				end
				s51:
				begin
					isb = msg[47:40];
					msg[47:40] = osb;
				end
				s52:
				begin
					isb = msg[55:48];
					msg[55:48] = osb;
				end
				s53:
				begin
					isb = msg[63:56];
					msg[63:56] = osb;
				end
				s54:
				begin
					isb = msg[71:64];
					msg[71:64] = osb;
				end
				s55:
				begin
					isb = msg[79:72];
					msg[79:72] = osb;
				end
				s56:
				begin
					isb = msg[87:80];
					msg[87:80] = osb;
				end
				s57:
				begin
					isb = msg[95:88];
					msg[95:88] = osb;
				end
				s58:
				begin
					isb = msg[103:96];
					msg[103:96] = osb;
				end
				s59:
				begin
					isb = msg[111:104];
					msg[111:104] = osb;
				end
				s60:
				begin
					isb = msg[119:112];
					msg[119:112] = osb;
				end
				s61:
				begin
					isb = msg[127:120];
					msg[127:120] = osb;
				end
				s62: 
            begin
					key = key_schedule[1023:896];
					msg = msg ^ key;
            end
				s63:
				begin
					imc = msg[31:0];
					msg[31:0] = omc;
				end
				s64:
				begin
					imc = msg[63:32];
					msg[63:32] = omc;
				end
				s65: 
            begin
					imc = msg[95:64];
					msg[95:64] = omc;
            end
				s66:
				begin
					imc = msg[127:96];
					msg[127:96] = omc;
				end
				s67:
            begin
					invSRin = msg;
					msg = invSRout;
				end
				s68:
				begin
					isb = msg[7:0];
					msg[7:0] = osb;
				end
				s69:
				begin
					isb = msg[15:8];
					msg[15:8 = osb;
				end
				s70:
				begin
					isb = msg[23:16];
					msg[23:16] = osb;
				end
				s71:
				begin
					isb = msg[31:24];
					msg[31:24] = osb;
				end
				s72:
				begin
					isb = msg[39:32];
					msg[39:32] = osb;
				end
				s73:
				begin
					isb = msg[47:40];
					msg[47:40] = osb;
				end
				s74:
				begin
					isb = msg[55:48];
					msg[55:48] = osb;
				end
				s75:
				begin
					isb = msg[63:56];
					msg[63:56] = osb;
				end
				s76:
				begin
					isb = msg[71:64];
					msg[71:64] = osb;
				end
				s77:
				begin
					isb = msg[79:72];
					msg[79:72] = osb;
				end
				s78:
				begin
					isb = msg[87:80];
					msg[87:80] = osb;
				end
				s79:
				begin
					isb = msg[95:88];
					msg[95:88] = osb;
				end
				s80:
				begin
					isb = msg[103:96];
					msg[103:96] = osb;
				end
				s81:
				begin
					isb = msg[111:104];
					msg[111:104] = osb;
				end
				s82:
				begin
					isb = msg[119:112];
					msg[119:112] = osb;
				end
				s83:
				begin
					isb = msg[127:120];
					msg[127:120] = osb;
				end
				s84: 
            begin
					key = key_schedule[895:768];
					msg = msg ^ key;
            end
				s85:
				begin
					imc = msg[31:0];
					msg[31:0] = omc;
				end
				s86:
				begin
					imc = msg[63:32];
					msg[63:32] = omc;
				end
				s87: 
            begin
					imc = msg[95:64];
					msg[95:64] = omc;
            end
				s88:
				begin
					imc = msg[127:96];
					msg[127:96] = omc;
				end
				s89:
            begin
					invSRin = msg;
					msg = invSRout;
				end
				s90:
				begin
					isb = msg[7:0];
					msg[7:0] = osb;
				end
				s91:
				begin
					isb = msg[15:8];
					msg[15:8 = osb;
				end
				s92:
				begin
					isb = msg[23:16];
					msg[23:16] = osb;
				end
				s93:
				begin
					isb = msg[31:24];
					msg[31:24] = osb;
				end
				s94:
				begin
					isb = msg[39:32];
					msg[39:32] = osb;
				end
				s95:
				begin
					isb = msg[47:40];
					msg[47:40] = osb;
				end
				s96:
				begin
					isb = msg[55:48];
					msg[55:48] = osb;
				end
				s97:
				begin
					isb = msg[63:56];
					msg[63:56] = osb;
				end
				s98:
				begin
					isb = msg[71:64];
					msg[71:64] = osb;
				end
				s99:
				begin
					isb = msg[79:72];
					msg[79:72] = osb;
				end
				s100:
				begin
					isb = msg[87:80];
					msg[87:80] = osb;
				end
				s101:
				begin
					isb = msg[95:88];
					msg[95:88] = osb;
				end
				s102:
				begin
					isb = msg[103:96];
					msg[103:96] = osb;
				end
				s103:
				begin
					isb = msg[111:104];
					msg[111:104] = osb;
				end
				s104:
				begin
					isb = msg[119:112];
					msg[119:112] = osb;
				end
				s105:
				begin
					isb = msg[127:120];
					msg[127:120] = osb;
				end
				s106: 
            begin
					key = key_schedule[767:640];
					msg = msg ^ key;
            end
				s107:
				begin
					imc = msg[31:0];
					msg[31:0] = omc;
				end
				s108:
				begin
					imc = msg[63:32];
					msg[63:32] = omc;
				end
				s109: 
            begin
					imc = msg[95:64];
					msg[95:64] = omc;
            end
				s110:
				begin
					imc = msg[127:96];
					msg[127:96] = omc;
				end
				s111:
            begin
					invSRin = msg;
					msg = invSRout;
				end
				s112:
				begin
					isb = msg[7:0];
					msg[7:0] = osb;
				end
				s113:
				begin
					isb = msg[15:8];
					msg[15:8 = osb;
				end
				s114:
				begin
					isb = msg[23:16];
					msg[23:16] = osb;
				end
				s115:
				begin
					isb = msg[31:24];
					msg[31:24] = osb;
				end
				s116:
				begin
					isb = msg[39:32];
					msg[39:32] = osb;
				end
				s117:
				begin
					isb = msg[47:40];
					msg[47:40] = osb;
				end
				s118:
				begin
					isb = msg[55:48];
					msg[55:48] = osb;
				end
				s119:
				begin
					isb = msg[63:56];
					msg[63:56] = osb;
				end
				s120:
				begin
					isb = msg[71:64];
					msg[71:64] = osb;
				end
				s121:
				begin
					isb = msg[79:72];
					msg[79:72] = osb;
				end
				s122:
				begin
					isb = msg[87:80];
					msg[87:80] = osb;
				end
				s123:
				begin
					isb = msg[95:88];
					msg[95:88] = osb;
				end
				s124:
				begin
					isb = msg[103:96];
					msg[103:96] = osb;
				end
				s125:
				begin
					isb = msg[111:104];
					msg[111:104] = osb;
				end
				s126:
				begin
					isb = msg[119:112];
					msg[119:112] = osb;
				end
				s127:
				begin
					isb = msg[127:120];
					msg[127:120] = osb;
				end
				s128: 
            begin
					key = key_schedule[639:512];
					msg = msg ^ key;
            end
				s129:
				begin
					imc = msg[31:0];
					msg[31:0] = omc;
				end
				s130:
				begin
					imc = msg[63:32];
					msg[63:32] = omc;
				end
				s131: 
            begin
					imc = msg[95:64];
					msg[95:64] = omc;
            end
				s132:
				begin
					imc = msg[127:96];
					msg[127:96] = omc;
				end
				s1:
            begin
					invSRin = msg;
					msg = invSRout;
				end
				s2:
				begin
					isb = msg[7:0];
					msg[7:0] = osb;
				end
				s3:
				begin
					isb = msg[15:8];
					msg[15:8 = osb;
				end
				s4:
				begin
					isb = msg[23:16];
					msg[23:16] = osb;
				end
				s5:
				begin
					isb = msg[31:24];
					msg[31:24] = osb;
				end
				s6:
				begin
					isb = msg[39:32];
					msg[39:32] = osb;
				end
				s7:
				begin
					isb = msg[47:40];
					msg[47:40] = osb;
				end
				s8:
				begin
					isb = msg[55:48];
					msg[55:48] = osb;
				end
				s9:
				begin
					isb = msg[63:56];
					msg[63:56] = osb;
				end
				s10:
				begin
					isb = msg[71:64];
					msg[71:64] = osb;
				end
				s11:
				begin
					isb = msg[79:72];
					msg[79:72] = osb;
				end
				s12:
				begin
					isb = msg[87:80];
					msg[87:80] = osb;
				end
				s13:
				begin
					isb = msg[95:88];
					msg[95:88] = osb;
				end
				s14:
				begin
					isb = msg[103:96];
					msg[103:96] = osb;
				end
				s15:
				begin
					isb = msg[111:104];
					msg[111:104] = osb;
				end
				s16:
				begin
					isb = msg[119:112];
					msg[119:112] = osb;
				end
				s17:
				begin
					isb = msg[127:120];
					msg[127:120] = osb;
				end
				s18: 
            begin
					key = key_schedule[1279:1152];
					msg = msg ^ key;
            end
				s19:
				begin
					imc = msg[31:0];
					msg[31:0] = omc;
				end
				s20:
				begin
					imc = msg[63:32];
					msg[63:32] = omc;
				end
				s21: 
            begin
					imc = msg[95:64];
					msg[95:64] = omc;
            end
				s22:
				begin
					imc = msg[127:96];
					msg[127:96] = omc;
				end
            default:
            begin
            end
        endcase
    end
							
							
endmodule
