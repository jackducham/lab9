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
	
	enum logic [7:0] {WAIT,s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15,s16,s17,s18,s19,s20,s21,s22,s23,s24,s25,
							s26,s27,s28,s29,s30,s31,s32,s33,s34,s35,s36,s37,s38,s39,s40,
							s41,s42,s43,s44,s45,s46,s47,s48,s49,s50,s51,s52,s53,s54,s55,s56,s57,s58,s59,s60,s61,s62,s63,s64,s65,
							s66,s67,s68,s69,s70,s71,s72,s73,s74,s75,s76,s77,s78,s79,s80,
							s81,s82,s83,s84,s85,s86,s87,s88,s89,s90,s91,s92,s93,s94,s95,s96,s97,s98,s99,s100,s101,s102,s103,
							s104,s105,s106,s107,s108,s109,s110,s111,s112,s113,s114,s115,s116,s117,s118,s119,s120,
							s121,s122,s123,s124,s125,s126,s127,s128,s129,s130,s131,s132,s133,s134,s135,s136,s137,s138,s139,s140,
							s141,s142,s143,s144,s145,s146,s147,s148,s149,s150,s151,s152,s153,s154,s155,s156,s157,s158,s159,s160,
							s161,s162,s163,s164,s165,s166,s167,s168,s169,s170,s171,s172,s173,s174,s175,s176,s177,s178,s179,s180,
							s181,s182,s183,s184,s185,s186,s187,s188,s189,s190,s191,s192,s193,s194,s195,s196,s197,s198,s199,s200,
							s201,s202,s203,s204,s205,s206,s207,s208,s209,s210,s211,s212,s213,s214,s215,s216,s217,
							DONE}, curr_state, next_state;

	assign invSRin = {128{1'b0}};
	assign key = {128{1'b0}};
	assign msg = {128{1'b0}};
	assign isb = {8{1'b0}};
	assign imc = {32{1'b0}};
							
	KeyExpansion keys(.clk(CLK),.Cipherkey(AES_KEY),.KeySchedule(key_schedule));					
	InvShiftRows invshiftrows(.data_in(invSRin),.data_out(invSRout));
	InvSubBytes  invsubbytes(.clk(CLK),.in(isb),.out(osb));
	InvMixColumns invmixcols(.in(imc),.out(omc));
	
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
		s40 : next_state = s41;
		s41 : next_state = s42;
		s42 : next_state = s43;
		s43 : next_state = s44;
		s44 : next_state = s45;
		s45 : next_state = s46;
		s46 : next_state = s47;
		s47 : next_state = s48;
		s48 : next_state = s49;
		s49 : next_state = s50;
		s50 : next_state = s51;
		s51 : next_state = s52;
		s52 : next_state = s53;
		s53 : next_state = s54;
		s54 : next_state = s55;
		s55 : next_state = s56;
		s56 : next_state = s57;
		s57 : next_state = s58;
		s58 : next_state = s59;
		s59 : next_state = s60;
		s60 : next_state = s61;
		s61 : next_state = s62;
		s62 : next_state = s63;
		s63 : next_state = s64;
		s64 : next_state = s65;
		s65 : next_state = s66;
		s66 : next_state = s67;
		s67 : next_state = s68;
		s68 : next_state = s69;
		s69 : next_state = s70;
		s70 : next_state = s71;
		s71 : next_state = s72;
		s72 : next_state = s73;
		s73 : next_state = s74;
		s74 : next_state = s75;
		s75 : next_state = s76;
		s76 : next_state = s77;
		s77 : next_state = s78;
		s78 : next_state = s79;
		s79 : next_state = s80;
		s80 : next_state = s81;
		s81 : next_state = s82;
		s82 : next_state = s83;
		s83 : next_state = s84;
		s84 : next_state = s85;
		s85 : next_state = s86;
		s86 : next_state = s87;
		s87 : next_state = s88;
		s88 : next_state = s89;
		s89 : next_state = s90;
		s90 : next_state = s91;
		s91 : next_state = s92;
		s92 : next_state = s93;
		s93 : next_state = s94;
		s94 : next_state = s95;
		s95 : next_state = s96;
		s96 : next_state = s97;
		s97 : next_state = s98;
		s98 : next_state = s99;
		s99 : next_state = s100;
		s100 : next_state = s101;
		s101 : next_state = s102;
		s102 : next_state = s103;
		s103 : next_state = s104;
		s104 : next_state = s105;
		s105 : next_state = s106;
		s106 : next_state = s107;
		s107 : next_state = s108;
		s108 : next_state = s109;
		s109 : next_state = s110;
		s110 : next_state = s111;
		s111 : next_state = s112;
		s112 : next_state = s113;
		s113 : next_state = s114;
		s114 : next_state = s115;
		s115 : next_state = s116;
		s116 : next_state = s117;
		s117 : next_state = s118;
		s118 : next_state = s119;
		s119 : next_state = s120;
		s120 : next_state = s121;
		s121 : next_state = s122;
		s122 : next_state = s123;
		s123 : next_state = s124;
		s124 : next_state = s125;
		s125 : next_state = s126;
		s126 : next_state = s127;
		s127 : next_state = s128;
		s128 : next_state = s129;
		s129 : next_state = s130;
		s130 : next_state = s131;
		s131 : next_state = s132;
		s132 : next_state = s133;
		s133 : next_state = s134;
		s134 : next_state = s135;
		s135 : next_state = s136;
		s136 : next_state = s137;
		s137 : next_state = s138;
		s138 : next_state = s139;
		s139 : next_state = s140;
		s140 : next_state = s141;
		s141 : next_state = s142;
		s142 : next_state = s143;
		s143 : next_state = s144;
		s144 : next_state = s145;
		s145 : next_state = s146;
		s146 : next_state = s147;
		s147 : next_state = s148;
		s148 : next_state = s149;
		s149 : next_state = s150;
		s150 : next_state = s151;
		s151 : next_state = s152;
		s152 : next_state = s153;
		s153 : next_state = s154;
		s154 : next_state = s155;
		s155 : next_state = s156;
		s156 : next_state = s157;
		s157 : next_state = s158;
		s158 : next_state = s159;
		s159 : next_state = s160;
		s160 : next_state = s161;
		s161 : next_state = s162;
		s162 : next_state = s163;
		s163 : next_state = s164;
		s164 : next_state = s165;
		s165 : next_state = s166;
		s166 : next_state = s167;
		s167 : next_state = s168;
		s168 : next_state = s169;
		s169 : next_state = s170;
		s170 : next_state = s171;
		s171 : next_state = s172;
		s172 : next_state = s173;
		s173 : next_state = s174;
		s174 : next_state = s175;
		s175 : next_state = s176;
		s176 : next_state = s177;
		s177 : next_state = s178;
		s178 : next_state = s179;
		s179 : next_state = s180;
		s180 : next_state = s181;
		s181 : next_state = s182;
		s182 : next_state = s183;
		s183 : next_state = s184;
		s184 : next_state = s185;
		s185 : next_state = s186;
		s186 : next_state = s187;
		s187 : next_state = s188;
		s188 : next_state = s189;
		s189 : next_state = s190;
		s190 : next_state = s191;
		s191 : next_state = s192;
		s192 : next_state = s193;
		s193 : next_state = s194;
		s194 : next_state = s195;
		s195 : next_state = s196;
		s196 : next_state = s197;
		s197 : next_state = s198;
		s198 : next_state = s199;
		s199 : next_state = s200;
		s200 : next_state = s201;
		s201 : next_state = s202;
		s202 : next_state = s203;
		s203 : next_state = s204;
		s204 : next_state = s205;
		s205 : next_state = s206;
		s206 : next_state = s207;
		s207 : next_state = s208;
		s208 : next_state = s209;
		s209 : next_state = s210;
		s210 : next_state = s211;
		s211 : next_state = s212;
		s212 : next_state = s213;
		s213 : next_state = s214;
		s214 : next_state = s215;
		s215 : next_state = s216;
		s216 : next_state = s217;
		s217 : next_state = DONE;
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
				s133:
            begin
					invSRin = msg;
					msg = invSRout;
				end
				s134:
				begin
					isb = msg[7:0];
					msg[7:0] = osb;
				end
				s135:
				begin
					isb = msg[15:8];
					msg[15:8 = osb;
				end
				s136:
				begin
					isb = msg[23:16];
					msg[23:16] = osb;
				end
				s137:
				begin
					isb = msg[31:24];
					msg[31:24] = osb;
				end
				s138:
				begin
					isb = msg[39:32];
					msg[39:32] = osb;
				end
				s139:
				begin
					isb = msg[47:40];
					msg[47:40] = osb;
				end
				s140:
				begin
					isb = msg[55:48];
					msg[55:48] = osb;
				end
				s141:
				begin
					isb = msg[63:56];
					msg[63:56] = osb;
				end
				s142:
				begin
					isb = msg[71:64];
					msg[71:64] = osb;
				end
				s143:
				begin
					isb = msg[79:72];
					msg[79:72] = osb;
				end
				s144:
				begin
					isb = msg[87:80];
					msg[87:80] = osb;
				end
				s145:
				begin
					isb = msg[95:88];
					msg[95:88] = osb;
				end
				s146:
				begin
					isb = msg[103:96];
					msg[103:96] = osb;
				end
				s147:
				begin
					isb = msg[111:104];
					msg[111:104] = osb;
				end
				s148:
				begin
					isb = msg[119:112];
					msg[119:112] = osb;
				end
				s149:
				begin
					isb = msg[127:120];
					msg[127:120] = osb;
				end
				s150: 
            begin
					key = key_schedule[511:384];
					msg = msg ^ key;
            end
				s151:
				begin
					imc = msg[31:0];
					msg[31:0] = omc;
				end
				s152:
				begin
					imc = msg[63:32];
					msg[63:32] = omc;
				end
				s153: 
            begin
					imc = msg[95:64];
					msg[95:64] = omc;
            end
				s154:
				begin
					imc = msg[127:96];
					msg[127:96] = omc;
				end
				s155:
            begin
					invSRin = msg;
					msg = invSRout;
				end
				s156:
				begin
					isb = msg[7:0];
					msg[7:0] = osb;
				end
				s157:
				begin
					isb = msg[15:8];
					msg[15:8 = osb;
				end
				s158:
				begin
					isb = msg[23:16];
					msg[23:16] = osb;
				end
				s159:
				begin
					isb = msg[31:24];
					msg[31:24] = osb;
				end
				s160:
				begin
					isb = msg[39:32];
					msg[39:32] = osb;
				end
				s161:
				begin
					isb = msg[47:40];
					msg[47:40] = osb;
				end
				s162:
				begin
					isb = msg[55:48];
					msg[55:48] = osb;
				end
				s163:
				begin
					isb = msg[63:56];
					msg[63:56] = osb;
				end
				s164:
				begin
					isb = msg[71:64];
					msg[71:64] = osb;
				end
				s165:
				begin
					isb = msg[79:72];
					msg[79:72] = osb;
				end
				s166:
				begin
					isb = msg[87:80];
					msg[87:80] = osb;
				end
				s167:
				begin
					isb = msg[95:88];
					msg[95:88] = osb;
				end
				s168:
				begin
					isb = msg[103:96];
					msg[103:96] = osb;
				end
				s169:
				begin
					isb = msg[111:104];
					msg[111:104] = osb;
				end
				s170:
				begin
					isb = msg[119:112];
					msg[119:112] = osb;
				end
				s171:
				begin
					isb = msg[127:120];
					msg[127:120] = osb;
				end
				s172: 
            begin
					key = key_schedule[383:256];
					msg = msg ^ key;
            end
				s173:
				begin
					imc = msg[31:0];
					msg[31:0] = omc;
				end
				s174:
				begin
					imc = msg[63:32];
					msg[63:32] = omc;
				end
				s175: 
            begin
					imc = msg[95:64];
					msg[95:64] = omc;
            end
				s176:
				begin
					imc = msg[127:96];
					msg[127:96] = omc;
				end
				s177:
            begin
					invSRin = msg;
					msg = invSRout;
				end
				s178:
				begin
					isb = msg[7:0];
					msg[7:0] = osb;
				end
				s179:
				begin
					isb = msg[15:8];
					msg[15:8 = osb;
				end
				s180:
				begin
					isb = msg[23:16];
					msg[23:16] = osb;
				end
				s181:
				begin
					isb = msg[31:24];
					msg[31:24] = osb;
				end
				s182:
				begin
					isb = msg[39:32];
					msg[39:32] = osb;
				end
				s183:
				begin
					isb = msg[47:40];
					msg[47:40] = osb;
				end
				s184:
				begin
					isb = msg[55:48];
					msg[55:48] = osb;
				end
				s185:
				begin
					isb = msg[63:56];
					msg[63:56] = osb;
				end
				s186:
				begin
					isb = msg[71:64];
					msg[71:64] = osb;
				end
				s187:
				begin
					isb = msg[79:72];
					msg[79:72] = osb;
				end
				s188:
				begin
					isb = msg[87:80];
					msg[87:80] = osb;
				end
				s189:
				begin
					isb = msg[95:88];
					msg[95:88] = osb;
				end
				s190:
				begin
					isb = msg[103:96];
					msg[103:96] = osb;
				end
				s191:
				begin
					isb = msg[111:104];
					msg[111:104] = osb;
				end
				s192:
				begin
					isb = msg[119:112];
					msg[119:112] = osb;
				end
				s193:
				begin
					isb = msg[127:120];
					msg[127:120] = osb;
				end
				s194: 
            begin
					key = key_schedule[255:128];
					msg = msg ^ key;
            end
				s195:
				begin
					imc = msg[31:0];
					msg[31:0] = omc;
				end
				s196:
				begin
					imc = msg[63:32];
					msg[63:32] = omc;
				end
				s197: 
            begin
					imc = msg[95:64];
					msg[95:64] = omc;
            end
				s198:
				begin
					imc = msg[127:96];
					msg[127:96] = omc;
				end
				s199:
            begin
					invSRin = msg;
					msg = invSRout;
				end
				s200:
				begin
					isb = msg[7:0];
					msg[7:0] = osb;
				end
				s201:
				begin
					isb = msg[15:8];
					msg[15:8 = osb;
				end
				s202:
				begin
					isb = msg[23:16];
					msg[23:16] = osb;
				end
				s203:
				begin
					isb = msg[31:24];
					msg[31:24] = osb;
				end
				s204:
				begin
					isb = msg[39:32];
					msg[39:32] = osb;
				end
				s205:
				begin
					isb = msg[47:40];
					msg[47:40] = osb;
				end
				s206:
				begin
					isb = msg[55:48];
					msg[55:48] = osb;
				end
				s207:
				begin
					isb = msg[63:56];
					msg[63:56] = osb;
				end
				s208:
				begin
					isb = msg[71:64];
					msg[71:64] = osb;
				end
				s209:
				begin
					isb = msg[79:72];
					msg[79:72] = osb;
				end
				s210:
				begin
					isb = msg[87:80];
					msg[87:80] = osb;
				end
				s211:
				begin
					isb = msg[95:88];
					msg[95:88] = osb;
				end
				s212:
				begin
					isb = msg[103:96];
					msg[103:96] = osb;
				end
				s213:
				begin
					isb = msg[111:104];
					msg[111:104] = osb;
				end
				s214:
				begin
					isb = msg[119:112];
					msg[119:112] = osb;
				end
				s215:
				begin
					isb = msg[127:120];
					msg[127:120] = osb;
				end
				s216: 
            begin
					key = key_schedule[127:0];
					msg = msg ^ key;
            end
				s217:
				begin
					AES_MSG_DEC = msg;
				end
				DONE:
				begin:
					AES_DONE = 1'b1;
				end:
            default:
            begin
					AES_DONE = 1'b0;
            end
        endcase
    end
							
							
endmodule
