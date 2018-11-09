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
					
				end
				s5:
				begin
				end
				s6: 
            begin
            end
				s7:
				begin
				end
				s8:
				begin
				end
            s9:
            begin
				end
				s10:
				begin
				end
				s11: 
            begin
            end
				s12:
				begin
				end
				s13:
				begin
				end
				s14: 
            begin
            end
				s15:
				begin
				end
				s16:
				begin
				end
            default:
            begin
            end
        endcase
    end
							
							
endmodule
