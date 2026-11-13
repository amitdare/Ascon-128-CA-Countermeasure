//`default_nettype none
`timescale 1ns / 1ps

//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date:    18:25:14 07/28/2026 
// Design Name: 
// Module Name:    Ascon_128 
// Project Name: 
// Target Devices: 
// Tool versions: 
// Description: 
//
// Dependencies: 
//
// Revision: 
// Revision 0.01 - File Created
// Additional Comments: 
//
//////////////////////////////////////////////////////////////////////////////////
module Ascon_128(
    input  wire                     clk,
    input  wire                     rst,
    input  wire                     start,
	 input [0:127]  						key,
    input [0:63]  						AD,
	 input [0:63]   						pT,
	 input [0:63] 							initial_value,
	 input [0:127] 						nonce,
	 

	 
	 output   [1:0]               phase,
    output   [3:0]               state,

    output   [1:0] 					ad_counter,
    output   [1:0] 					pt_counter,

    output                       start_ip,
    output                       start_ad,
    output                       start_pt,
    output                       start_fp,


    output                       ct_load,
    output                       tag_load,
    output                       ca_run,

    output                       busy,
    output                       stop,
	 
	 output [0:63] ciphertext,

	 output  [0:63]      Tag0,
	 output  [0:63]      Tag1,
	 output              set7,
	 output              set1,
	 output 					key0_xor,
	 output        		key1_xor,
	 output          		ad_counter_decrease,
	 output          		pt_counter_decrease,
	 output          		AP_to_PP_trans,
    output          		PP_to_FP_trans

    );
    reg [1:0] 					ad_block_count;
    reg [1:0] 					pt_block_count;
	 reg [0:63]             AD_pad;
	 initial 
	           begin
				    ad_block_count <= 2'b10;
					 pt_block_count <= 2'b01;
					 AD_pad         <=  64'h8000000000000000;
				  end

wire [0:63] key_p1,key_p2,nonce_p1,nonce_p2;

wire [0:63] after_xor_lr_x3,after_xor_lr_x4,xor_before_pt_x4,xor_before_pt_x4_final;


wire  [0:63] after_lr_x0,after_lr_x1,after_lr_x2,after_lr_x3,after_lr_x4;
wire  [0:63] after_lr_x0_ca,after_lr_x1_ca,after_lr_x2_ca,after_lr_x3_ca,after_lr_x4_ca;

wire [0:63] mux4x2_outside1,mux4x2_out2_t,mux4x2_out2_f,mux4x2_out3_t,mux4x2_out3_f;
wire [0:63] mux4x2_outside2,Tag0_t,Tag1_t;

wire [0:7] shifted_r;
wire [7:0] round;

wire [0:63]  x0;
wire [0:63]  x1;
wire [0:63]  x2;
wire [0:63]  x3;
wire [0:63]  x4;
//wire  [0:63]      Tag0_t;
//wire  [0:63]      Tag1_t;
wire [4:0] ca_state;



wire [0:4] sbox1_ip,sbox2_ip,sbox3_ip,sbox4_ip,sbox5_ip,sbox6_ip,sbox7_ip,sbox8_ip,sbox9_ip,sbox10_ip;
wire [0:4] sbox11_ip,sbox12_ip,sbox13_ip,sbox14_ip,sbox15_ip,sbox16_ip,sbox17_ip,sbox18_ip,sbox19_ip,sbox20_ip;
wire [0:4] sbox21_ip,sbox22_ip,sbox23_ip,sbox24_ip,sbox25_ip,sbox26_ip,sbox27_ip,sbox28_ip,sbox29_ip,sbox30_ip;
wire [0:4] sbox31_ip,sbox32_ip,sbox33_ip,sbox34_ip,sbox35_ip,sbox36_ip,sbox37_ip,sbox38_ip,sbox39_ip,sbox40_ip;
wire [0:4] sbox41_ip,sbox42_ip,sbox43_ip,sbox44_ip,sbox45_ip,sbox46_ip,sbox47_ip,sbox48_ip,sbox49_ip,sbox50_ip;
wire [0:4] sbox51_ip,sbox52_ip,sbox53_ip,sbox54_ip,sbox55_ip,sbox56_ip,sbox57_ip,sbox58_ip,sbox59_ip,sbox60_ip;
wire [0:4] sbox61_ip,sbox62_ip,sbox63_ip,sbox64_ip;

wire [0:4] sbox1_op,sbox2_op,sbox3_op,sbox4_op,sbox5_op,sbox6_op,sbox7_op,sbox8_op,sbox9_op,sbox10_op;
wire [0:4] sbox11_op,sbox12_op,sbox13_op,sbox14_op,sbox15_op,sbox16_op,sbox17_op,sbox18_op,sbox19_op,sbox20_op;
wire [0:4] sbox21_op,sbox22_op,sbox23_op,sbox24_op,sbox25_op,sbox26_op,sbox27_op,sbox28_op,sbox29_op,sbox30_op;
wire [0:4] sbox31_op,sbox32_op,sbox33_op,sbox34_op,sbox35_op,sbox36_op,sbox37_op,sbox38_op,sbox39_op,sbox40_op;
wire [0:4] sbox41_op,sbox42_op,sbox43_op,sbox44_op,sbox45_op,sbox46_op,sbox47_op,sbox48_op,sbox49_op,sbox50_op;
wire [0:4] sbox51_op,sbox52_op,sbox53_op,sbox54_op,sbox55_op,sbox56_op,sbox57_op,sbox58_op,sbox59_op,sbox60_op;
wire [0:4] sbox61_op,sbox62_op,sbox63_op,sbox64_op;



wire [0:63]  mux4x2_out1,mux4x2_out2,mux4x2_out3,mux4x2_out4,mux4x2_out5;
wire [0:63]  x2_temp;
wire [0:63] xor_ad_pt;
wire [0:63] after_sb_x0,after_sb_x1,after_sb_x2,after_sb_x3,after_sb_x4;
wire [0:7]  intermediate_value,intermediate_value_f;
wire                       state1;



wire [5:0] ca_state1,ca_state2;

assign key_p1 = key[0:63];
assign key_p2 = key[64:127];
assign nonce_p1 = nonce[0:63];
assign nonce_p2 = nonce[64:127];

mux2x1_64bit mux_1_inside(.inp1(initial_value),.inp2(after_lr_x0),.ctrl_signal(start),.out(mux4x2_out1));//0 for encryption  1 for decryption
mux2x1_64bit mux_2_inside(.inp1(key_p1),.inp2(after_lr_x1),.ctrl_signal(start),.out(mux4x2_out2));//0 for encryption  1 for decryption
mux2x1_64bit mux_3_inside(.inp1(key_p2),.inp2(after_lr_x2),.ctrl_signal(start),.out(mux4x2_out3));//0 for encryption  1 for decryption

assign mux4x2_out2_t = mux4x2_out2 ^ key_p1;
assign mux4x2_out3_t = mux4x2_out3 ^ key_p2;

mux2x1_64bit mux_2_inside_f(.inp1(mux4x2_out2),.inp2(mux4x2_out2_t),.ctrl_signal(key0_xor),.out(mux4x2_out2_f));//0 for encryption  1 for decryption
mux2x1_64bit mux_3_inside_f(.inp1(mux4x2_out3),.inp2(mux4x2_out3_t),.ctrl_signal(key1_xor),.out(mux4x2_out3_f));//0 for encryption  1 for decryption


mux2x1_64bit mux_4_inside(.inp1(nonce_p1),.inp2(mux4x2_outside1),.ctrl_signal(start),.out(mux4x2_out4));//0 for encryption  1 for decryption
mux2x1_64bit mux_5_inside(.inp1(nonce_p2),.inp2(mux4x2_outside2),.ctrl_signal(start),.out(mux4x2_out5));//0 for encryption  1 for decryption

assign xor_before_pt_x4 = mux4x2_out5 ^ 64'h0000000000000001;
mux2x1_64bit mux_6_inside(.inp1(mux4x2_out5),.inp2(xor_before_pt_x4),.ctrl_signal(AP_to_PP_trans),.out(xor_before_pt_x4_final));//0 for encryption  1 for decryption


/*
assign xor_ad_pt =
    (ad_counter != 1) ?
        ((state[2] & state[3] ) ?
            (mux4x2_out1 ^ AD) :
            mux4x2_out1)
    :
        (((pt_counter != 1) &&
          (state[2] & state[3] )) ?
            (mux4x2_out1 ^ pT) :
            mux4x2_out1);
*/
assign xor_ad_pt = (start_ip)? (state[0] & state[1]& state[3])?(mux4x2_out1 ^ AD) :mux4x2_out1
                 :((start_ad)&(state[0] & state[1]& state[3])& (ad_counter==2))?(mux4x2_out1 ^ AD_pad) :
					  ((state[0] & state[1]& state[3])& (ad_counter==1))? (mux4x2_out1 ^ pT) :(PP_to_FP_trans)?(mux4x2_out1 ^ AD_pad):mux4x2_out1;
					  
					  



pipo_64_bit_reg     R_x0 (.clk(clk),.clear(clear),.pi(xor_ad_pt),.po(x0));
pipo_64_bit_reg     R_x1 (.clk(clk),.clear(clear),.pi(mux4x2_out2_f),.po(x1));
pipo_64_bit_reg     R_x2 (.clk(clk),.clear(clear),.pi(mux4x2_out3_f),.po(x2));
pipo_64_bit_reg     R_x3 (.clk(clk),.clear(clear),.pi(mux4x2_out4),.po(x3));
pipo_64_bit_reg     R_x4 (.clk(clk),.clear(clear),.pi(xor_before_pt_x4_final),.po(x4));

pipo_64_bit_reg     R_ct (.clk(ct_load),.clear(clear),.pi(x0),.po(ciphertext));
assign Tag0_t = after_lr_x3_ca^key_p1;
assign Tag1_t = after_lr_x3_ca^key_p2;
pipo_64_bit_reg     R_T0 (.clk(tag_load),.clear(clear),.pi(Tag0_t),.po(Tag0));
pipo_64_bit_reg     R_T1 (.clk(tag_load),.clear(clear),.pi(Tag1_t),.po(Tag1));



// --- Add Round Constant ---
 assign round[3:0] = state[3:0];
 assign round[7:4] = 4'b0000;
 assign shifted_r = (round) << 4;
 assign intermediate_value = (8'b11110000 ^ shifted_r) ^ (round);
 assign intermediate_value_f  =(start_ip)?(state==12)?8'h96:intermediate_value:((start_ad)&(state==12))?8'h96:((start_pt)&(state==12))?8'hf0:intermediate_value;
 assign x2_temp[56:63]  = x2[56:63] ^ intermediate_value_f;
 assign x2_temp[0:55] = x2[0:55];
 
 
 
 
 //add sbox operation////////
 assign sbox1_ip[0]= x0[0];
 assign sbox1_ip[1]= x1[0];
 assign sbox1_ip[2]= x2_temp[0];
 assign sbox1_ip[3]= x3[0];
 assign sbox1_ip[4]= x4[0];
 
	 assign sbox2_ip[0]= x0[1];
	 assign sbox2_ip[1]= x1[1];
	 assign sbox2_ip[2]= x2_temp[1];
	 assign sbox2_ip[3]= x3[1];
	 assign sbox2_ip[4]= x4[1];
	 
	 assign sbox3_ip[0]= x0[2];
	 assign sbox3_ip[1]= x1[2];
	 assign sbox3_ip[2]= x2_temp[2];
	 assign sbox3_ip[3]= x3[2];
	 assign sbox3_ip[4]= x4[2];

	 assign sbox4_ip[0]= x0[3];
	 assign sbox4_ip[1]= x1[3];
	 assign sbox4_ip[2]= x2_temp[3];
	 assign sbox4_ip[3]= x3[3];
	 assign sbox4_ip[4]= x4[3];
	 
	 assign sbox5_ip[0]= x0[4];
	 assign sbox5_ip[1]= x1[4];
	 assign sbox5_ip[2]= x2_temp[4];
	 assign sbox5_ip[3]= x3[4];
	 assign sbox5_ip[4]= x4[4];


	 assign sbox6_ip[0]= x0[5];
	 assign sbox6_ip[1]= x1[5];
	 assign sbox6_ip[2]= x2_temp[5];
	 assign sbox6_ip[3]= x3[5];
	 assign sbox6_ip[4]= x4[5];
	 
	 assign sbox7_ip[0]= x0[6];
	 assign sbox7_ip[1]= x1[6];
	 assign sbox7_ip[2]= x2_temp[6];
	 assign sbox7_ip[3]= x3[6];
	 assign sbox7_ip[4]= x4[6];
	 
	 assign sbox8_ip[0]= x0[7];
	 assign sbox8_ip[1]= x1[7];
	 assign sbox8_ip[2]= x2_temp[7];
	 assign sbox8_ip[3]= x3[7];
	 assign sbox8_ip[4]= x4[7];


	 assign sbox9_ip[0]= x0[8];
	 assign sbox9_ip[1]= x1[8];
	 assign sbox9_ip[2]= x2_temp[8];
	 assign sbox9_ip[3]= x3[8];
	 assign sbox9_ip[4]= x4[8];
	 
	 assign sbox10_ip[0]= x0[9];
	 assign sbox10_ip[1]= x1[9];
	 assign sbox10_ip[2]= x2_temp[9];
	 assign sbox10_ip[3]= x3[9];
	 assign sbox10_ip[4]= x4[9];
	 
	 assign sbox11_ip[0]= 		x0[10];
	 assign sbox11_ip[1]= 		x1[10];
	 assign sbox11_ip[2]= x2_temp[10];
	 assign sbox11_ip[3]= 		x3[10];
	 assign sbox11_ip[4]= 		x4[10];
	 
	 assign sbox12_ip[0]= 		x0[11];
	 assign sbox12_ip[1]= 		x1[11];
	 assign sbox12_ip[2]= x2_temp[11];
	 assign sbox12_ip[3]= 		x3[11];
	 assign sbox12_ip[4]= 		x4[11];


	 assign sbox13_ip[0]= 		x0[12];
	 assign sbox13_ip[1]= 		x1[12];
	 assign sbox13_ip[2]= x2_temp[12];
	 assign sbox13_ip[3]= 		x3[12];
	 assign sbox13_ip[4]= 		x4[12];


	 assign sbox14_ip[0]= 		x0[13];
	 assign sbox14_ip[1]= 		x1[13];
	 assign sbox14_ip[2]= x2_temp[13];
	 assign sbox14_ip[3]= 		x3[13];
	 assign sbox14_ip[4]= 		x4[13];
	 
	 assign sbox15_ip[0]= 		x0[14];
	 assign sbox15_ip[1]= 		x1[14];
	 assign sbox15_ip[2]= x2_temp[14];
	 assign sbox15_ip[3]= 		x3[14];
	 assign sbox15_ip[4]= 		x4[14];


	 assign sbox16_ip[0]= 		x0[15];
	 assign sbox16_ip[1]= 		x1[15];
	 assign sbox16_ip[2]= x2_temp[15];
	 assign sbox16_ip[3]= 		x3[15];
	 assign sbox16_ip[4]= 		x4[15];
	 
	 assign sbox17_ip[0]= 		x0[16];
	 assign sbox17_ip[1]= 		x1[16];
	 assign sbox17_ip[2]= x2_temp[16];
	 assign sbox17_ip[3]= 		x3[16];
	 assign sbox17_ip[4]= 		x4[16];


	 assign sbox18_ip[0]= 		x0[17];
	 assign sbox18_ip[1]= 		x1[17];
	 assign sbox18_ip[2]= x2_temp[17];
	 assign sbox18_ip[3]= 		x3[17];
	 assign sbox18_ip[4]= 		x4[17];
	 
	 assign sbox19_ip[0]= 		x0[18];
	 assign sbox19_ip[1]= 		x1[18];
	 assign sbox19_ip[2]= x2_temp[18];
	 assign sbox19_ip[3]= 		x3[18];
	 assign sbox19_ip[4]= 		x4[18];


	 assign sbox20_ip[0]= 		x0[19];
	 assign sbox20_ip[1]= 		x1[19];
	 assign sbox20_ip[2]= x2_temp[19];
	 assign sbox20_ip[3]= 		x3[19];
	 assign sbox20_ip[4]= 		x4[19];
	 
	 
	 assign sbox21_ip[0]= 		x0[20];
	 assign sbox21_ip[1]= 		x1[20];
	 assign sbox21_ip[2]= x2_temp[20];
	 assign sbox21_ip[3]= 		x3[20];
	 assign sbox21_ip[4]= 		x4[20];
	 
	 assign sbox22_ip[0]= 		x0[21];
	 assign sbox22_ip[1]= 		x1[21];
	 assign sbox22_ip[2]= x2_temp[21];
	 assign sbox22_ip[3]= 		x3[21];
	 assign sbox22_ip[4]= 		x4[21];

	 assign sbox23_ip[0]= 		x0[22];
	 assign sbox23_ip[1]= 		x1[22];
	 assign sbox23_ip[2]= x2_temp[22];
	 assign sbox23_ip[3]= 		x3[22];
	 assign sbox23_ip[4]= 		x4[22];

	 assign sbox24_ip[0]= 		x0[23];
	 assign sbox24_ip[1]= 		x1[23];
	 assign sbox24_ip[2]= x2_temp[23];
	 assign sbox24_ip[3]= 		x3[23];
	 assign sbox24_ip[4]= 		x4[23];
	 
	 assign sbox25_ip[0]= 		x0[24];
	 assign sbox25_ip[1]= 		x1[24];
	 assign sbox25_ip[2]= x2_temp[24];
	 assign sbox25_ip[3]= 		x3[24];
	 assign sbox25_ip[4]= 		x4[24];

	 assign sbox26_ip[0]= 		x0[25];
	 assign sbox26_ip[1]= 		x1[25];
	 assign sbox26_ip[2]= x2_temp[25];
	 assign sbox26_ip[3]= 		x3[25];
	 assign sbox26_ip[4]= 		x4[25];
	 
	 assign sbox27_ip[0]= 		x0[26];
	 assign sbox27_ip[1]= 		x1[26];
	 assign sbox27_ip[2]= x2_temp[26];
	 assign sbox27_ip[3]= 		x3[26];
	 assign sbox27_ip[4]= 		x4[26];

	 assign sbox28_ip[0]= 		x0[27];
	 assign sbox28_ip[1]= 		x1[27];
	 assign sbox28_ip[2]= x2_temp[27];
	 assign sbox28_ip[3]= 		x3[27];
	 assign sbox28_ip[4]= 		x4[27];
	 
	 assign sbox29_ip[0]= 		x0[28];
	 assign sbox29_ip[1]= 		x1[28];
	 assign sbox29_ip[2]= x2_temp[28];
	 assign sbox29_ip[3]= 		x3[28];
	 assign sbox29_ip[4]= 		x4[28];

	 assign sbox30_ip[0]= 		x0[29];
	 assign sbox30_ip[1]= 		x1[29];
	 assign sbox30_ip[2]= x2_temp[29];
	 assign sbox30_ip[3]= 		x3[29];
	 assign sbox30_ip[4]= 		x4[29];
	 
	 assign sbox31_ip[0]= 		x0[30];
	 assign sbox31_ip[1]= 		x1[30];
	 assign sbox31_ip[2]= x2_temp[30];
	 assign sbox31_ip[3]= 		x3[30];
	 assign sbox31_ip[4]= 		x4[30];
	 
	 assign sbox32_ip[0]= 		x0[31];
	 assign sbox32_ip[1]= 		x1[31];
	 assign sbox32_ip[2]= x2_temp[31];
	 assign sbox32_ip[3]= 		x3[31];
	 assign sbox32_ip[4]= 		x4[31];

	 assign sbox33_ip[0]= 		x0[32];
	 assign sbox33_ip[1]= 		x1[32];
	 assign sbox33_ip[2]= x2_temp[32];
	 assign sbox33_ip[3]= 		x3[32];
	 assign sbox33_ip[4]= 		x4[32];

	 assign sbox34_ip[0]= 		x0[33];
	 assign sbox34_ip[1]= 		x1[33];
	 assign sbox34_ip[2]= x2_temp[33];
	 assign sbox34_ip[3]= 		x3[33];
	 assign sbox34_ip[4]= 		x4[33];
	 
	 assign sbox35_ip[0]= 		x0[34];
	 assign sbox35_ip[1]= 		x1[34];
	 assign sbox35_ip[2]= x2_temp[34];
	 assign sbox35_ip[3]= 		x3[34];
	 assign sbox35_ip[4]= 		x4[34];

	 assign sbox36_ip[0]= 		x0[35];
	 assign sbox36_ip[1]= 		x1[35];
	 assign sbox36_ip[2]= x2_temp[35];
	 assign sbox36_ip[3]= 		x3[35];
	 assign sbox36_ip[4]= 		x4[35];
	 
	 assign sbox37_ip[0]= 		x0[36];
	 assign sbox37_ip[1]= 		x1[36];
	 assign sbox37_ip[2]= x2_temp[36];
	 assign sbox37_ip[3]= 		x3[36];
	 assign sbox37_ip[4]= 		x4[36];

	 assign sbox38_ip[0]= 		x0[37];
	 assign sbox38_ip[1]= 		x1[37];
	 assign sbox38_ip[2]= x2_temp[37];
	 assign sbox38_ip[3]= 		x3[37];
	 assign sbox38_ip[4]= 		x4[37];
	
	 assign sbox39_ip[0]= 		x0[38];
	 assign sbox39_ip[1]= 		x1[38];
	 assign sbox39_ip[2]= x2_temp[38];
	 assign sbox39_ip[3]= 		x3[38];
	 assign sbox39_ip[4]= 		x4[38];

	 assign sbox40_ip[0]= 		x0[39];
	 assign sbox40_ip[1]= 		x1[39];
	 assign sbox40_ip[2]= x2_temp[39];
	 assign sbox40_ip[3]= 		x3[39];
	 assign sbox40_ip[4]= 		x4[39];
	 
	 assign sbox41_ip[0]= 		x0[40];
	 assign sbox41_ip[1]= 		x1[40];
	 assign sbox41_ip[2]= x2_temp[40];
	 assign sbox41_ip[3]= 		x3[40];
	 assign sbox41_ip[4]= 		x4[40];
	 
	 assign sbox42_ip[0]= 		x0[41];
	 assign sbox42_ip[1]= 		x1[41];
	 assign sbox42_ip[2]= x2_temp[41];
	 assign sbox42_ip[3]= 		x3[41];
	 assign sbox42_ip[4]= 		x4[41];

	 assign sbox43_ip[0]= 		x0[42];
	 assign sbox43_ip[1]= 		x1[42];
	 assign sbox43_ip[2]= x2_temp[42];
	 assign sbox43_ip[3]= 		x3[42];
	 assign sbox43_ip[4]= 		x4[42];

	 assign sbox44_ip[0]= 		x0[43];
	 assign sbox44_ip[1]= 		x1[43];
	 assign sbox44_ip[2]= x2_temp[43];
	 assign sbox44_ip[3]= 		x3[43];
	 assign sbox44_ip[4]= 		x4[43];
	 
	 assign sbox45_ip[0]= 		x0[44];
	 assign sbox45_ip[1]= 		x1[44];
	 assign sbox45_ip[2]= x2_temp[44];
	 assign sbox45_ip[3]= 		x3[44];
	 assign sbox45_ip[4]= 		x4[44];

	 assign sbox46_ip[0]= 		x0[45];
	 assign sbox46_ip[1]= 		x1[45];
	 assign sbox46_ip[2]= x2_temp[45];
	 assign sbox46_ip[3]= 		x3[45];
	 assign sbox46_ip[4]= 		x4[45];
	 
	 assign sbox47_ip[0]= 		x0[46];
	 assign sbox47_ip[1]= 		x1[46];
	 assign sbox47_ip[2]= x2_temp[46];
	 assign sbox47_ip[3]= 		x3[46];
	 assign sbox47_ip[4]= 		x4[46];

	 assign sbox48_ip[0]= 		x0[47];
	 assign sbox48_ip[1]= 		x1[47];
	 assign sbox48_ip[2]= x2_temp[47];
	 assign sbox48_ip[3]= 		x3[47];
	 assign sbox48_ip[4]= 		x4[47];

	 assign sbox49_ip[0]= 		x0[48];
	 assign sbox49_ip[1]= 		x1[48];
	 assign sbox49_ip[2]= x2_temp[48];
	 assign sbox49_ip[3]= 		x3[48];
	 assign sbox49_ip[4]= 		x4[48];

	 assign sbox50_ip[0]= 		x0[49];
	 assign sbox50_ip[1]= 		x1[49];
	 assign sbox50_ip[2]= x2_temp[49];
	 assign sbox50_ip[3]= 		x3[49];
	 assign sbox50_ip[4]= 		x4[49];

	 assign sbox51_ip[0]= 		x0[50];
	 assign sbox51_ip[1]= 		x1[50];
	 assign sbox51_ip[2]= x2_temp[50];
	 assign sbox51_ip[3]= 		x3[50];
	 assign sbox51_ip[4]= 		x4[50];
	 
	 assign sbox52_ip[0]= 		x0[51];
	 assign sbox52_ip[1]= 		x1[51];
	 assign sbox52_ip[2]= x2_temp[51];
	 assign sbox52_ip[3]= 		x3[51];
	 assign sbox52_ip[4]= 		x4[51];

	 assign sbox53_ip[0]= 		x0[52];
	 assign sbox53_ip[1]= 		x1[52];
	 assign sbox53_ip[2]= x2_temp[52];
	 assign sbox53_ip[3]= 		x3[52];
	 assign sbox53_ip[4]= 		x4[52];

	 assign sbox54_ip[0]= 		x0[53];
	 assign sbox54_ip[1]= 		x1[53];
	 assign sbox54_ip[2]= x2_temp[53];
	 assign sbox54_ip[3]= 		x3[53];
	 assign sbox54_ip[4]= 		x4[53];
	 
	 assign sbox55_ip[0]= 		x0[54];
	 assign sbox55_ip[1]= 		x1[54];
	 assign sbox55_ip[2]= x2_temp[54];
	 assign sbox55_ip[3]= 		x3[54];
	 assign sbox55_ip[4]= 		x4[54];

	 assign sbox56_ip[0]= 		x0[55];
	 assign sbox56_ip[1]= 		x1[55];
	 assign sbox56_ip[2]= x2_temp[55];
	 assign sbox56_ip[3]= 		x3[55];
	 assign sbox56_ip[4]= 		x4[55];
	
	 assign sbox57_ip[0]= 		x0[56];
	 assign sbox57_ip[1]= 		x1[56];  
	 assign sbox57_ip[2]= x2_temp[56];
	 assign sbox57_ip[3]= 		x3[56];
	 assign sbox57_ip[4]= 		x4[56];

	 assign sbox58_ip[0]= 		x0[57];
	 assign sbox58_ip[1]= 		x1[57];
	 assign sbox58_ip[2]= x2_temp[57];
	 assign sbox58_ip[3]= 		x3[57];
	 assign sbox58_ip[4]= 		x4[57];

	 assign sbox59_ip[0]= 		x0[58];
	 assign sbox59_ip[1]= 		x1[58];
	 assign sbox59_ip[2]= x2_temp[58];
	 assign sbox59_ip[3]= 		x3[58];
	 assign sbox59_ip[4]= 		x4[58];

	 assign sbox60_ip[0]= 		x0[59];
	 assign sbox60_ip[1]= 		x1[59];
	 assign sbox60_ip[2]= x2_temp[59];
	 assign sbox60_ip[3]= 		x3[59];
	 assign sbox60_ip[4]= 		x4[59];
	 
	 assign sbox61_ip[0]= 		x0[60];
	 assign sbox61_ip[1]= 		x1[60];
	 assign sbox61_ip[2]= x2_temp[60];
	 assign sbox61_ip[3]= 		x3[60];
	 assign sbox61_ip[4]= 		x4[60];
	 
	 assign sbox62_ip[0]= 		x0[61];
	 assign sbox62_ip[1]= 		x1[61];
	 assign sbox62_ip[2]= x2_temp[61];
	 assign sbox62_ip[3]= 		x3[61];
	 assign sbox62_ip[4]= 		x4[61];

	 assign sbox63_ip[0]= 		x0[62];
	 assign sbox63_ip[1]= 		x1[62];
	 assign sbox63_ip[2]= x2_temp[62];
	 assign sbox63_ip[3]= 		x3[62];
	 assign sbox63_ip[4]= 		x4[62];

	 assign sbox64_ip[0]= 		x0[63];
	 assign sbox64_ip[1]= 		x1[63];
	 assign sbox64_ip[2]= x2_temp[63];
	 assign sbox64_ip[3]= 		x3[63];
	 assign sbox64_ip[4]= 		x4[63];
	 
	 
	 ascon_sbox   sb1 (.a(sbox1_ip), .b(sbox1_op));
	 ascon_sbox   sb2 (.a(sbox2_ip), .b(sbox2_op));
	 ascon_sbox   sb3 (.a(sbox3_ip), .b(sbox3_op));
	 ascon_sbox   sb4 (.a(sbox4_ip), .b(sbox4_op));
	 ascon_sbox   sb5 (.a(sbox5_ip), .b(sbox5_op));
	 ascon_sbox   sb6 (.a(sbox6_ip), .b(sbox6_op));
	 ascon_sbox   sb7 (.a(sbox7_ip), .b(sbox7_op));
	 ascon_sbox   sb8 (.a(sbox8_ip), .b(sbox8_op));
	 ascon_sbox   sb9 (.a(sbox9_ip), .b(sbox9_op));
	 ascon_sbox   sb10(.a(sbox10_ip),.b(sbox10_op));
	 ascon_sbox   sb11(.a(sbox11_ip),.b(sbox11_op));
	 ascon_sbox   sb12(.a(sbox12_ip),.b(sbox12_op));
	 ascon_sbox   sb13(.a(sbox13_ip),.b(sbox13_op));
	 ascon_sbox   sb14(.a(sbox14_ip),.b(sbox14_op));
	 ascon_sbox   sb15(.a(sbox15_ip),.b(sbox15_op));
	 ascon_sbox   sb16(.a(sbox16_ip),.b(sbox16_op));
	 ascon_sbox   sb17(.a(sbox17_ip),.b(sbox17_op));
	 ascon_sbox   sb18(.a(sbox18_ip),.b(sbox18_op));
	 ascon_sbox   sb19(.a(sbox19_ip),.b(sbox19_op));
	 ascon_sbox   sb20(.a(sbox20_ip),.b(sbox20_op));
	 ascon_sbox   sb21(.a(sbox21_ip),.b(sbox21_op));
	 ascon_sbox   sb22(.a(sbox22_ip),.b(sbox22_op));
	 ascon_sbox   sb23(.a(sbox23_ip),.b(sbox23_op));
	 ascon_sbox   sb24(.a(sbox24_ip),.b(sbox24_op));
	 ascon_sbox   sb25(.a(sbox25_ip),.b(sbox25_op));
	 ascon_sbox   sb26(.a(sbox26_ip),.b(sbox26_op));
	 ascon_sbox   sb27(.a(sbox27_ip),.b(sbox27_op));
	 ascon_sbox   sb28(.a(sbox28_ip),.b(sbox28_op));
	 ascon_sbox   sb29(.a(sbox29_ip),.b(sbox29_op));
	 ascon_sbox   sb30(.a(sbox30_ip),.b(sbox30_op));
	 ascon_sbox   sb31(.a(sbox31_ip),.b(sbox31_op));
	 ascon_sbox   sb32(.a(sbox32_ip),.b(sbox32_op));
	 ascon_sbox   sb33(.a(sbox33_ip),.b(sbox33_op));
	 ascon_sbox   sb34(.a(sbox34_ip),.b(sbox34_op));
	 ascon_sbox   sb35(.a(sbox35_ip),.b(sbox35_op));
	 ascon_sbox   sb36(.a(sbox36_ip),.b(sbox36_op));
	 ascon_sbox   sb37(.a(sbox37_ip),.b(sbox37_op));
	 ascon_sbox   sb38(.a(sbox38_ip),.b(sbox38_op));
	 ascon_sbox   sb39(.a(sbox39_ip),.b(sbox39_op));
	 ascon_sbox   sb40(.a(sbox40_ip),.b(sbox40_op));
	 ascon_sbox   sb41(.a(sbox41_ip),.b(sbox41_op));
	 ascon_sbox   sb42(.a(sbox42_ip),.b(sbox42_op));
	 ascon_sbox   sb43(.a(sbox43_ip),.b(sbox43_op));
	 ascon_sbox   sb44(.a(sbox44_ip),.b(sbox44_op));
	 ascon_sbox   sb45(.a(sbox45_ip),.b(sbox45_op));
	 ascon_sbox   sb46(.a(sbox46_ip),.b(sbox46_op));
	 ascon_sbox   sb47(.a(sbox47_ip),.b(sbox47_op));
	 ascon_sbox   sb48(.a(sbox48_ip),.b(sbox48_op));
	 ascon_sbox   sb49(.a(sbox49_ip),.b(sbox49_op));
	 ascon_sbox   sb50(.a(sbox50_ip),.b(sbox50_op));
	 ascon_sbox   sb51(.a(sbox51_ip),.b(sbox51_op));
	 ascon_sbox   sb52(.a(sbox52_ip),.b(sbox52_op));
	 ascon_sbox   sb53(.a(sbox53_ip),.b(sbox53_op));
	 ascon_sbox   sb54(.a(sbox54_ip),.b(sbox54_op));
	 ascon_sbox   sb55(.a(sbox55_ip),.b(sbox55_op));
	 ascon_sbox   sb56(.a(sbox56_ip),.b(sbox56_op));
	 ascon_sbox   sb57(.a(sbox57_ip),.b(sbox57_op));
	 ascon_sbox   sb58(.a(sbox58_ip),.b(sbox58_op));
	 ascon_sbox   sb59(.a(sbox59_ip),.b(sbox59_op));
	 ascon_sbox   sb60(.a(sbox60_ip),.b(sbox60_op));
	 ascon_sbox   sb61(.a(sbox61_ip),.b(sbox61_op));
	 ascon_sbox   sb62(.a(sbox62_ip),.b(sbox62_op));
	 ascon_sbox   sb63(.a(sbox63_ip),.b(sbox63_op));
	 ascon_sbox   sb64(.a(sbox64_ip),.b(sbox64_op));

    /////after sb x0 ///
	 assign after_sb_x0[0] 	= sbox1_op[0];
	 assign after_sb_x0[1] 	= sbox2_op[0];
	 assign after_sb_x0[2] 	= sbox3_op[0];
	 assign after_sb_x0[3] 	= sbox4_op[0];
	 assign after_sb_x0[4] 	= sbox5_op[0];
	 assign after_sb_x0[5] 	= sbox6_op[0];
	 assign after_sb_x0[6] 	= sbox7_op[0];
	 assign after_sb_x0[7] 	= sbox8_op[0];
	 assign after_sb_x0[8] 	= sbox9_op[0];
	 assign after_sb_x0[9] 	= sbox10_op[0];
	 assign after_sb_x0[10] = sbox11_op[0];
	 assign after_sb_x0[11] = sbox12_op[0];
	 assign after_sb_x0[12] = sbox13_op[0];
	 assign after_sb_x0[13] = sbox14_op[0];
	 assign after_sb_x0[14] = sbox15_op[0];
	 assign after_sb_x0[15] = sbox16_op[0];
	 assign after_sb_x0[16] = sbox17_op[0];
	 assign after_sb_x0[17] = sbox18_op[0];
	 assign after_sb_x0[18] = sbox19_op[0];
	 assign after_sb_x0[19] = sbox20_op[0];
	 assign after_sb_x0[20] = sbox21_op[0];
	 assign after_sb_x0[21] = sbox22_op[0];
	 assign after_sb_x0[22] = sbox23_op[0];
	 assign after_sb_x0[23] = sbox24_op[0];
	 assign after_sb_x0[24] = sbox25_op[0];
	 assign after_sb_x0[25] = sbox26_op[0];
	 assign after_sb_x0[26] = sbox27_op[0];
	 assign after_sb_x0[27] = sbox28_op[0];
	 assign after_sb_x0[28] = sbox29_op[0];
	 assign after_sb_x0[29] = sbox30_op[0];
	 assign after_sb_x0[30] = sbox31_op[0];
	 assign after_sb_x0[31] = sbox32_op[0];
	 assign after_sb_x0[32] = sbox33_op[0];
	 assign after_sb_x0[33] = sbox34_op[0];
	 assign after_sb_x0[34] = sbox35_op[0];
	 assign after_sb_x0[35] = sbox36_op[0];
	 assign after_sb_x0[36] = sbox37_op[0];
	 assign after_sb_x0[37] = sbox38_op[0];
	 assign after_sb_x0[38] = sbox39_op[0];
	 assign after_sb_x0[39] = sbox40_op[0];
	 assign after_sb_x0[40] = sbox41_op[0];
	 assign after_sb_x0[41] = sbox42_op[0];
	 assign after_sb_x0[42] = sbox43_op[0];
	 assign after_sb_x0[43] = sbox44_op[0];
	 assign after_sb_x0[44] = sbox45_op[0];
	 assign after_sb_x0[45] = sbox46_op[0];
	 assign after_sb_x0[46] = sbox47_op[0];
	 assign after_sb_x0[47] = sbox48_op[0];
	 assign after_sb_x0[48] = sbox49_op[0];
	 assign after_sb_x0[49] = sbox50_op[0];
	 assign after_sb_x0[50] = sbox51_op[0];
	 assign after_sb_x0[51] = sbox52_op[0];
	 assign after_sb_x0[52] = sbox53_op[0];
	 assign after_sb_x0[53] = sbox54_op[0];
	 assign after_sb_x0[54] = sbox55_op[0];
	 assign after_sb_x0[55] = sbox56_op[0];
	 assign after_sb_x0[56] = sbox57_op[0];
	 assign after_sb_x0[57] = sbox58_op[0];
	 assign after_sb_x0[58] = sbox59_op[0];
	 assign after_sb_x0[59] = sbox60_op[0];
	 assign after_sb_x0[60] = sbox61_op[0];
	 assign after_sb_x0[61] = sbox62_op[0];
	 assign after_sb_x0[62] = sbox63_op[0];
	 assign after_sb_x0[63] = sbox64_op[0];
	 
	 ///////////////////////after sb x1////////////// 
	 assign after_sb_x1[0] 	=  sbox1_op[1];
	 assign after_sb_x1[1] 	=  sbox2_op[1];
	 assign after_sb_x1[2] 	=  sbox3_op[1];
	 assign after_sb_x1[3] 	=  sbox4_op[1];
	 assign after_sb_x1[4] 	=  sbox5_op[1];
	 assign after_sb_x1[5] 	=  sbox6_op[1];
	 assign after_sb_x1[6] 	=  sbox7_op[1];
	 assign after_sb_x1[7] 	=  sbox8_op[1];
	 assign after_sb_x1[8] 	=  sbox9_op[1];
	 assign after_sb_x1[9] 	= sbox10_op[1];
	 assign after_sb_x1[10] = sbox11_op[1];
	 assign after_sb_x1[11] = sbox12_op[1];
	 assign after_sb_x1[12] = sbox13_op[1];
	 assign after_sb_x1[13] = sbox14_op[1];
	 assign after_sb_x1[14] = sbox15_op[1];
	 assign after_sb_x1[15] = sbox16_op[1];
	 assign after_sb_x1[16] = sbox17_op[1];
	 assign after_sb_x1[17] = sbox18_op[1];
	 assign after_sb_x1[18] = sbox19_op[1];
	 assign after_sb_x1[19] = sbox20_op[1];
	 assign after_sb_x1[20] = sbox21_op[1];
	 assign after_sb_x1[21] = sbox22_op[1];
	 assign after_sb_x1[22] = sbox23_op[1];
	 assign after_sb_x1[23] = sbox24_op[1];
	 assign after_sb_x1[24] = sbox25_op[1];
	 assign after_sb_x1[25] = sbox26_op[1];
	 assign after_sb_x1[26] = sbox27_op[1];
	 assign after_sb_x1[27] = sbox28_op[1];
	 assign after_sb_x1[28] = sbox29_op[1];
	 assign after_sb_x1[29] = sbox30_op[1];
	 assign after_sb_x1[30] = sbox31_op[1];
	 assign after_sb_x1[31] = sbox32_op[1];
	 assign after_sb_x1[32] = sbox33_op[1];
	 assign after_sb_x1[33] = sbox34_op[1];
	 assign after_sb_x1[34] = sbox35_op[1];
	 assign after_sb_x1[35] = sbox36_op[1];
	 assign after_sb_x1[36] = sbox37_op[1];
	 assign after_sb_x1[37] = sbox38_op[1];
	 assign after_sb_x1[38] = sbox39_op[1];
	 assign after_sb_x1[39] = sbox40_op[1];
	 assign after_sb_x1[40] = sbox41_op[1];
	 assign after_sb_x1[41] = sbox42_op[1];
	 assign after_sb_x1[42] = sbox43_op[1];
	 assign after_sb_x1[43] = sbox44_op[1];
	 assign after_sb_x1[44] = sbox45_op[1];
	 assign after_sb_x1[45] = sbox46_op[1];
	 assign after_sb_x1[46] = sbox47_op[1];
	 assign after_sb_x1[47] = sbox48_op[1];
	 assign after_sb_x1[48] = sbox49_op[1];
	 assign after_sb_x1[49] = sbox50_op[1];
	 assign after_sb_x1[50] = sbox51_op[1];
	 assign after_sb_x1[51] = sbox52_op[1];
	 assign after_sb_x1[52] = sbox53_op[1];
	 assign after_sb_x1[53] = sbox54_op[1];
	 assign after_sb_x1[54] = sbox55_op[1];
	 assign after_sb_x1[55] = sbox56_op[1];
	 assign after_sb_x1[56] = sbox57_op[1];
	 assign after_sb_x1[57] = sbox58_op[1];
	 assign after_sb_x1[58] = sbox59_op[1];
	 assign after_sb_x1[59] = sbox60_op[1];
	 assign after_sb_x1[60] = sbox61_op[1];
	 assign after_sb_x1[61] = sbox62_op[1];
	 assign after_sb_x1[62] = sbox63_op[1];
	 assign after_sb_x1[63] = sbox64_op[1];
	 
	 ///////////////////////after sb x2////////////// 
	 assign after_sb_x2[0] 	=  sbox1_op[2];
	 assign after_sb_x2[1] 	=  sbox2_op[2];
	 assign after_sb_x2[2] 	=  sbox3_op[2];
	 assign after_sb_x2[3] 	=  sbox4_op[2];
	 assign after_sb_x2[4] 	=  sbox5_op[2];
	 assign after_sb_x2[5] 	=  sbox6_op[2];
	 assign after_sb_x2[6] 	=  sbox7_op[2];
	 assign after_sb_x2[7] 	=  sbox8_op[2];
	 assign after_sb_x2[8] 	=  sbox9_op[2];
	 assign after_sb_x2[9] 	= sbox10_op[2];
	 assign after_sb_x2[10] = sbox11_op[2];
	 assign after_sb_x2[11] = sbox12_op[2];
	 assign after_sb_x2[12] = sbox13_op[2];
	 assign after_sb_x2[13] = sbox14_op[2];
	 assign after_sb_x2[14] = sbox15_op[2];
	 assign after_sb_x2[15] = sbox16_op[2];
	 assign after_sb_x2[16] = sbox17_op[2];
	 assign after_sb_x2[17] = sbox18_op[2];
	 assign after_sb_x2[18] = sbox19_op[2];
	 assign after_sb_x2[19] = sbox20_op[2];
	 assign after_sb_x2[20] = sbox21_op[2];
	 assign after_sb_x2[21] = sbox22_op[2];
	 assign after_sb_x2[22] = sbox23_op[2];
	 assign after_sb_x2[23] = sbox24_op[2];
	 assign after_sb_x2[24] = sbox25_op[2];
	 assign after_sb_x2[25] = sbox26_op[2];
	 assign after_sb_x2[26] = sbox27_op[2];
	 assign after_sb_x2[27] = sbox28_op[2];
	 assign after_sb_x2[28] = sbox29_op[2];
	 assign after_sb_x2[29] = sbox30_op[2];
	 assign after_sb_x2[30] = sbox31_op[2];
	 assign after_sb_x2[31] = sbox32_op[2];
	 assign after_sb_x2[32] = sbox33_op[2];
	 assign after_sb_x2[33] = sbox34_op[2];
	 assign after_sb_x2[34] = sbox35_op[2];
	 assign after_sb_x2[35] = sbox36_op[2];
	 assign after_sb_x2[36] = sbox37_op[2];
	 assign after_sb_x2[37] = sbox38_op[2];
	 assign after_sb_x2[38] = sbox39_op[2];
	 assign after_sb_x2[39] = sbox40_op[2];
	 assign after_sb_x2[40] = sbox41_op[2];
	 assign after_sb_x2[41] = sbox42_op[2];
	 assign after_sb_x2[42] = sbox43_op[2];
	 assign after_sb_x2[43] = sbox44_op[2];
	 assign after_sb_x2[44] = sbox45_op[2];
	 assign after_sb_x2[45] = sbox46_op[2];
	 assign after_sb_x2[46] = sbox47_op[2];
	 assign after_sb_x2[47] = sbox48_op[2];
	 assign after_sb_x2[48] = sbox49_op[2];
	 assign after_sb_x2[49] = sbox50_op[2];
	 assign after_sb_x2[50] = sbox51_op[2];
	 assign after_sb_x2[51] = sbox52_op[2];
	 assign after_sb_x2[52] = sbox53_op[2];
	 assign after_sb_x2[53] = sbox54_op[2];
	 assign after_sb_x2[54] = sbox55_op[2];
	 assign after_sb_x2[55] = sbox56_op[2];
	 assign after_sb_x2[56] = sbox57_op[2];
	 assign after_sb_x2[57] = sbox58_op[2];
	 assign after_sb_x2[58] = sbox59_op[2];
	 assign after_sb_x2[59] = sbox60_op[2];
	 assign after_sb_x2[60] = sbox61_op[2];
	 assign after_sb_x2[61] = sbox62_op[2];
	 assign after_sb_x2[62] = sbox63_op[2];
	 assign after_sb_x2[63] = sbox64_op[2];
	 ///////////////////////after sb xafter_sb_x0[43] 3////////////// 
	 assign after_sb_x3[0] 	=  sbox1_op[3];
	 assign after_sb_x3[1] 	=  sbox2_op[3];
	 assign after_sb_x3[2] 	=  sbox3_op[3];
	 assign after_sb_x3[3] 	=  sbox4_op[3];
	 assign after_sb_x3[4] 	=  sbox5_op[3];
	 assign after_sb_x3[5] 	=  sbox6_op[3];
	 assign after_sb_x3[6] 	=  sbox7_op[3];
	 assign after_sb_x3[7] 	=  sbox8_op[3];
	 assign after_sb_x3[8] 	=  sbox9_op[3];
	 assign after_sb_x3[9] 	= sbox10_op[3];
	 assign after_sb_x3[10] = sbox11_op[3];
	 assign after_sb_x3[11] = sbox12_op[3];
	 assign after_sb_x3[12] = sbox13_op[3];
	 assign after_sb_x3[13] = sbox14_op[3];
	 assign after_sb_x3[14] = sbox15_op[3];
	 assign after_sb_x3[15] = sbox16_op[3];
	 assign after_sb_x3[16] = sbox17_op[3];
	 assign after_sb_x3[17] = sbox18_op[3];
	 assign after_sb_x3[18] = sbox19_op[3];
	 assign after_sb_x3[19] = sbox20_op[3];
	 assign after_sb_x3[20] = sbox21_op[3];
	 assign after_sb_x3[21] = sbox22_op[3];
	 assign after_sb_x3[22] = sbox23_op[3];
	 assign after_sb_x3[23] = sbox24_op[3];
	 assign after_sb_x3[24] = sbox25_op[3];
	 assign after_sb_x3[25] = sbox26_op[3];
	 assign after_sb_x3[26] = sbox27_op[3];
	 assign after_sb_x3[27] = sbox28_op[3];
	 assign after_sb_x3[28] = sbox29_op[3];
	 assign after_sb_x3[29] = sbox30_op[3];
	 assign after_sb_x3[30] = sbox31_op[3];
	 assign after_sb_x3[31] = sbox32_op[3];
	 assign after_sb_x3[32] = sbox33_op[3];
	 assign after_sb_x3[33] = sbox34_op[3];
	 assign after_sb_x3[34] = sbox35_op[3];
	 assign after_sb_x3[35] = sbox36_op[3];
	 assign after_sb_x3[36] = sbox37_op[3];
	 assign after_sb_x3[37] = sbox38_op[3];
	 assign after_sb_x3[38] = sbox39_op[3];
	 assign after_sb_x3[39] = sbox40_op[3];
	 assign after_sb_x3[40] = sbox41_op[3];
	 assign after_sb_x3[41] = sbox42_op[3];
	 assign after_sb_x3[42] = sbox43_op[3];
	 assign after_sb_x3[43] = sbox44_op[3];
	 assign after_sb_x3[44] = sbox45_op[3];
	 assign after_sb_x3[45] = sbox46_op[3];
	 assign after_sb_x3[46] = sbox47_op[3];
	 assign after_sb_x3[47] = sbox48_op[3];
	 assign after_sb_x3[48] = sbox49_op[3];
	 assign after_sb_x3[49] = sbox50_op[3];
	 assign after_sb_x3[50] = sbox51_op[3];
	 assign after_sb_x3[51] = sbox52_op[3];
	 assign after_sb_x3[52] = sbox53_op[3];
	 assign after_sb_x3[53] = sbox54_op[3];
	 assign after_sb_x3[54] = sbox55_op[3];
	 assign after_sb_x3[55] = sbox56_op[3];
	 assign after_sb_x3[56] = sbox57_op[3];
	 assign after_sb_x3[57] = sbox58_op[3];
	 assign after_sb_x3[58] = sbox59_op[3];
	 assign after_sb_x3[59] = sbox60_op[3];
	 assign after_sb_x3[60] = sbox61_op[3];
	 assign after_sb_x3[61] = sbox62_op[3];
	 assign after_sb_x3[62] = sbox63_op[3];
	 assign after_sb_x3[63] = sbox64_op[3];
	 
	 ///////////////////////after sb x4////////////// 
	 assign after_sb_x4[0] 	=  sbox1_op[4];
	 assign after_sb_x4[1] 	=  sbox2_op[4];
	 assign after_sb_x4[2] 	=  sbox3_op[4];
	 assign after_sb_x4[3] 	=  sbox4_op[4];
	 assign after_sb_x4[4] 	=  sbox5_op[4];
	 assign after_sb_x4[5] 	=  sbox6_op[4];
	 assign after_sb_x4[6] 	=  sbox7_op[4];
	 assign after_sb_x4[7] 	=  sbox8_op[4];
	 assign after_sb_x4[8] 	=  sbox9_op[4];
	 assign after_sb_x4[9] 	= sbox10_op[4];
	 assign after_sb_x4[10] = sbox11_op[4];
	 assign after_sb_x4[11] = sbox12_op[4];
	 assign after_sb_x4[12] = sbox13_op[4];
	 assign after_sb_x4[13] = sbox14_op[4];
	 assign after_sb_x4[14] = sbox15_op[4];
	 assign after_sb_x4[15] = sbox16_op[4];
	 assign after_sb_x4[16] = sbox17_op[4];
	 assign after_sb_x4[17] = sbox18_op[4];
	 assign after_sb_x4[18] = sbox19_op[4];
	 assign after_sb_x4[19] = sbox20_op[4];
	 assign after_sb_x4[20] = sbox21_op[4];
	 assign after_sb_x4[21] = sbox22_op[4];
	 assign after_sb_x4[22] = sbox23_op[4];
	 assign after_sb_x4[23] = sbox24_op[4];
	 assign after_sb_x4[24] = sbox25_op[4];
	 assign after_sb_x4[25] = sbox26_op[4];
	 assign after_sb_x4[26] = sbox27_op[4];
	 assign after_sb_x4[27] = sbox28_op[4];
	 assign after_sb_x4[28] = sbox29_op[4];
	 assign after_sb_x4[29] = sbox30_op[4];
	 assign after_sb_x4[30] = sbox31_op[4];
	 assign after_sb_x4[31] = sbox32_op[4];
	 assign after_sb_x4[32] = sbox33_op[4];
	 assign after_sb_x4[33] = sbox34_op[4];
	 assign after_sb_x4[34] = sbox35_op[4];
	 assign after_sb_x4[35] = sbox36_op[4];
	 assign after_sb_x4[36] = sbox37_op[4];
	 assign after_sb_x4[37] = sbox38_op[4];
	 assign after_sb_x4[38] = sbox39_op[4];
	 assign after_sb_x4[39] = sbox40_op[4];
	 assign after_sb_x4[40] = sbox41_op[4];
	 assign after_sb_x4[41] = sbox42_op[4];
	 assign after_sb_x4[42] = sbox43_op[4];
	 assign after_sb_x4[43] = sbox44_op[4];
	 assign after_sb_x4[44] = sbox45_op[4];
	 assign after_sb_x4[45] = sbox46_op[4];
	 assign after_sb_x4[46] = sbox47_op[4];
	 assign after_sb_x4[47] = sbox48_op[4];
	 assign after_sb_x4[48] = sbox49_op[4];
	 assign after_sb_x4[49] = sbox50_op[4];
	 assign after_sb_x4[50] = sbox51_op[4];
	 assign after_sb_x4[51] = sbox52_op[4];
	 assign after_sb_x4[52] = sbox53_op[4];
	 assign after_sb_x4[53] = sbox54_op[4];
	 assign after_sb_x4[54] = sbox55_op[4];
	 assign after_sb_x4[55] = sbox56_op[4];
	 assign after_sb_x4[56] = sbox57_op[4];
	 assign after_sb_x4[57] = sbox58_op[4];
	 assign after_sb_x4[58] = sbox59_op[4];
	 assign after_sb_x4[59] = sbox60_op[4];
	 assign after_sb_x4[60] = sbox61_op[4];
	 assign after_sb_x4[61] = sbox62_op[4];
	 assign after_sb_x4[62] = sbox63_op[4];
	 assign after_sb_x4[63] = sbox64_op[4];

	 assign after_lr_x0 = after_sb_x0 ^ ((after_sb_x0 >> 19)|(after_sb_x0<<45)) ^ ((after_sb_x0>>28)|(after_sb_x0<<36));
	 assign after_lr_x1 = after_sb_x1 ^ ((after_sb_x1>> 61)|(after_sb_x1<< 3)) ^ ((after_sb_x1>> 39)|(after_sb_x1<< 25));
	 assign after_lr_x2 = after_sb_x2 ^ ((after_sb_x2>> 1)|(after_sb_x2<< 63)) ^ ((after_sb_x2>> 6)|(after_sb_x2<< 58));
	 assign after_lr_x3 = after_sb_x3 ^ ((after_sb_x3>> 10)|(after_sb_x3<< 54)) ^ ((after_sb_x3>> 17)|(after_sb_x3<< 47));
	 assign after_lr_x4 = after_sb_x4 ^ ((after_sb_x4>> 7)|(after_sb_x4<< 57)) ^ ((after_sb_x4>> 41)|(after_sb_x4<< 23));
	 
	 assign ca_state1 ={ca_state,1'b1}; 
	 assign ca_state2 ={ca_state,1'b0};
	 
	 assign after_lr_x0_ca = after_sb_x0 ^ ((after_sb_x0 >> 19)|(after_sb_x0<<45)) ^ ((after_sb_x0>>28)|(after_sb_x0<<36));
	 assign after_lr_x1_ca = after_sb_x1 ^ ((after_sb_x1>> 61)|(after_sb_x1<< 3)) ^ ((after_sb_x1>> 39)|(after_sb_x1<< 25));
	 assign after_lr_x2_ca = after_sb_x2 ^ ((after_sb_x2>> 1)|(after_sb_x2<< 63)) ^ ((after_sb_x2>> 6)|(after_sb_x2<< 58));
	 assign after_lr_x3_ca = after_sb_x3 ^ ((after_sb_x3>> 10)|(after_sb_x3<< 54)) ^ ((after_sb_x3>> 17)|(after_sb_x3<< 47))^ ((after_sb_x3>>ca_state1)|(after_sb_x3<<64-ca_state1));
	 assign after_lr_x4_ca = after_sb_x4 ^ ((after_sb_x4>> 7)|(after_sb_x4<< 57)) ^ ((after_sb_x4>> 41)|(after_sb_x4<< 23))^ ((after_sb_x4>>ca_state2)|(after_sb_x4<<64-ca_state2));

    assign after_xor_lr_x3=after_lr_x3 ^ key[0:63];
	 assign after_xor_lr_x4=after_lr_x4 ^ key[64:127];
	 
	 mux2x1_64bit mux_1_outside(.inp1(after_lr_x3),.inp2(after_xor_lr_x3),.ctrl_signal(( state[1] & state[0] & state[3]) && (start_ip == 1)),.out(mux4x2_outside1));//0 for encryption  1 for decryption
	 mux2x1_64bit mux_2_outside(.inp1(after_lr_x4),.inp2(after_xor_lr_x4),.ctrl_signal(( state[1] & state[0] & state[3]) && (start_ip == 1)),.out(mux4x2_outside2));//0 for encryption  1 for decryption


    mlca_5bit CA1(
    .clk(clk),
    .rst(~ca_run),
    .seed(key[123:127]),
    .ca_state(ca_state)
);

 Controller  C_128 (
        .clk                  (clk),
        .rst                  (rst),
        .start                (start),
        .ad_block_count       (ad_block_count),
        .pt_block_count       (pt_block_count),
        .phase                (phase),
        .state                (state),
        .ad_counter           (ad_counter),
        .pt_counter           (pt_counter),
        .start_ip             (start_ip),
        .start_ad             (start_ad),
        .start_pt             (start_pt),
        .start_fp             (start_fp),
        .phase_begin	            (state1),
        .set7                 (set7),
        .set1                 (set1),
        .ad_counter_decrease  (ad_counter_decrease),
        .pt_counter_decrease  (pt_counter_decrease),
        .AP_to_PP_trans          (AP_to_PP_trans),
        .PP_to_FP_trans  (PP_to_FP_trans),
        .ct_load              (ct_load),
        .tag_load             (tag_load),
        .ca_run               (ca_run),
        .busy                 (busy),
        .stop                 (stop),
		  .key0_xor					(key0_xor),
		  .key1_xor					(key1_xor)
    );

endmodule

module Controller(
    input  wire                     clk,
    input  wire                     rst,
    input  wire                     start,

    input  wire [1:0] 					ad_block_count,
    input  wire [1:0] 					pt_block_count,
	 
	 

    output reg  [1:0]               phase,
    output reg  [3:0]               state,

    output reg  [1:0] 					ad_counter,
    output reg  [1:0] 					pt_counter,

    output reg                      start_ip,
    output reg                      start_ad,
    output reg                      start_pt,
    output reg                      start_fp,

    output reg                      phase_begin,
    output reg                      set7,
    output reg                      set1,

    output reg                      ad_counter_decrease,
    output reg                      pt_counter_decrease,

    output reg                      AP_to_PP_trans,
    output reg                      PP_to_FP_trans,

    output reg                      ct_load,
    output reg                      tag_load,
    output reg                      ca_run,

    output reg                      busy,
    output reg                      stop,
	 output reg                      key0_xor,
	 output reg                   	key1_xor
		
		);

    localparam PHASE_INIT  = 2'd0;
    localparam PHASE_AD    = 2'd1;
    localparam PHASE_PT    = 2'd2;
    localparam PHASE_FINAL = 2'd3;

    reg running;

    /*
     * Sequential phase, state and block-counter control.
     */
    always @(posedge clk) begin
        if (rst) begin
            phase      <= PHASE_INIT;
            state      <= 4'd0;
            ad_counter <= {2'b00};
            pt_counter <= {2'b00};
            running    <= 1'b0;
        end else begin

            /*
             * Start a new ASCON operation.
             */
            if (start && !running) begin
                phase      <= PHASE_INIT;
                state      <= 4'd1;
                ad_counter <= ad_block_count;
                pt_counter <= pt_block_count;
                running    <= 1'b1;
            end
            else if (running) begin
                case (phase)

                    /*
                     * Initialization phase:
                     * state 0 through state 11.
                     */
                    PHASE_INIT: begin
                        if (state < 4'd12) begin
                            state <= state + 1'b1;
                        end else begin
                            /*
                             * Initialization has completed.
                             * If AD exists, enter AD at state 4.
                             * Otherwise skip directly to PT or finalization.
                             */
                            if (ad_counter != 0) begin
                                phase <= PHASE_AD;
                                state <= 4'd7;
                            end
                            else if (pt_counter != 0) begin
                                phase <= PHASE_PT;
                                state <= 4'd7;
                            end
                            else begin
                                phase <= PHASE_FINAL;
                                state <= 4'd1;
                            end
                        end
                    end

                    /*
                     * Associated-data processing:
                     * state 4 through state 11.
                     */
                    PHASE_AD: begin
                        if (state < 4'd12) begin
                            state <= state + 1'b1;
                        end else begin
                            /*
                             * State 11 completes one AD block.
                             */
                            if (ad_counter != 0)
                                ad_counter <= ad_counter - 1'b1;

                            /*
                             * Current value 1 means decrement produces zero.
                             */
                            if (ad_counter <= 1) begin
                                if (pt_counter != 0) begin
                                    phase <= PHASE_PT;
                                    state <= 4'd7;
                                end else begin
                                    phase <= PHASE_FINAL;
                                    state <= 4'd1;
                                end
                            end else begin
                                /*
                                 * More AD blocks remain.
                                 */
                                state <= 4'd7;
                            end
                        end
                    end

                    /*
                     * Plaintext processing:
                     * state 4 through state 11.
                     */
                    PHASE_PT: begin
                        if (state < 4'd12) begin
                            state <= state + 1'b1;
                        end else begin
                            /*
                             * State 11 completes one plaintext block.
                             */
                            if (pt_counter != 0)
                                pt_counter <= pt_counter - 1'b1;

                            if (pt_counter <= 1) begin
                                phase <= PHASE_FINAL;
                                state <= 4'd1;
                            end else begin
                                /*
                                 * More plaintext blocks remain.
                                 */
                                state <= 4'd7;
                            end
                        end
                    end

                    /*
                     * Finalization:
                     * state 0 through state 12.
                     */
                    PHASE_FINAL: begin
                        if (state < 4'd13) begin
                            state <= state + 1'b1;
                        end else begin
                            /*
                             * Final state reached. Return to idle.
                             */
                            state   <= 4'd1;
                            phase   <= PHASE_INIT;
                            running <= 1'b0;
                        end
                    end

                    default: begin
                        phase   <= PHASE_INIT;
                        state   <= 4'd1;
                        running <= 1'b0;
                    end
                endcase
            end
        end
    end

    /*
     * Combinational output decoder.
     *
     * All outputs are given defaults to prevent inferred latches.
     */
    always @(*) begin
        start_ip             = 1'b0;
        start_ad             = 1'b0;
        start_pt             = 1'b0;
        start_fp             = 1'b0;

        phase_begin              = 1'b0;
        set7                 = 1'b0;
        set1                 = 1'b0;

        ad_counter_decrease  = 1'b0;
        pt_counter_decrease  = 1'b0;

        AP_to_PP_trans          = 1'b0;
        PP_to_FP_trans  = 1'b0;

        ct_load              = 1'b0;
        tag_load             = 1'b0;
        ca_run               = 1'b0;

        busy                 = running;
        stop                 = 1'b0;

        if (running) begin
            case (phase)

                /*
                 * Initialization phase outputs.
                 */
                PHASE_INIT: begin
                    start_ip = 1'b1;

                    case (state)
                        4'd1: begin
                            phase_begin = 1'b1;
                        end

                        4'd2, 4'd3, 4'd4, 4'd5, 4'd6,
                        4'd7, 4'd8, 4'd9, 4'd10, 4'd11: begin
                            phase_begin = 1'b0;
                        end

                        4'd12: begin
                            phase_begin = 1'b0;
                            set7    = 1'b1;
                        end

                        default: begin
                            phase_begin = 1'b0;
                        end
                    endcase
                end

                /*
                 * Associated-data phase outputs.
                 */
                PHASE_AD: begin
                    start_ad = 1'b1;

                    case (state)
                        4'd7: begin
                            phase_begin             = 1'b1;
                            ad_counter_decrease = 1'b0;
                            AP_to_PP_trans         = 1'b0;
                            set7                = 1'b0;
                        end

                         4'd8, 4'd9, 4'd10, 4'd10: begin
                            phase_begin             = 1'b0;
                            ad_counter_decrease = 1'b0;
                            set7                = 1'b0;
                        end
                        4'd11: begin
												if (ad_counter <= 1)
													AP_to_PP_trans = 1'b1;
								       end
                        4'd12: begin
                            phase_begin             = 1'b0;
                            ad_counter_decrease = 1'b1;
                            set7                = 1'b1;
									 AP_to_PP_trans = 1'b0;
									 if (ad_counter <= 1)
									       ct_load             = 1'b1;
                            /*
                             * Assert on the final AD block.
                             */
                            
                        end

                        default: begin
                            phase_begin = 1'b0;
                        end
                    endcase
                end

                /*
                 * Plaintext phase outputs.
                 */
                PHASE_PT: begin
                    start_pt = 1'b1;

                    case (state)
                        4'd7: begin
                            phase_begin             = 1'b1;
                            set7                = 1'b0;
                            pt_counter_decrease = 1'b0;
                            ct_load             = 1'b0;
									 key0_xor            = 1'b0;
									 key1_xor				= 1'b0;

                            /*
                             * This pulse marks entry from AD into PT.
                             * It is also asserted when AD was skipped.
                             */
                            PP_to_FP_trans = 1'b0;
                        end

                         4'd8, 4'd9, 4'd10: begin
                            phase_begin             = 1'b0;
                            pt_counter_decrease = 1'b0;
                            PP_to_FP_trans = 1'b0;
                            ct_load             = 1'b0;
                        end
								4'd11: begin
												if (pt_counter <= 1)
													PP_to_FP_trans = 1'b1;
											   key0_xor            = 1'b1;
									         key1_xor				= 1'b1;

								       end

                        4'd12: begin
                            phase_begin             = 1'b0;
                            pt_counter_decrease = 1'b1;
                            PP_to_FP_trans = 1'b0;
									 key0_xor            = 1'b0;
									 key1_xor				= 1'b0;

                            /*
                             * For the final PT block, prepare transition
                             * to finalization. Otherwise restart at state 4.
                             */
                            if (pt_counter <= 1) begin
                                set7 = 1'b0;
                                set1 = 1'b1;
                            end else begin
                                set7 = 1'b1;
                                set1 = 1'b0;
                            end
                        end

                        default: begin
                            phase_begin = 1'b0;
                        end
                    endcase
                end

                /*
                 * Finalization phase outputs.
                 */
                PHASE_FINAL: begin
                    start_fp = 1'b1;

                    case (state)
                        4'd1: begin
                            phase_begin = 1'b1;
                            set1    = 1'b0;
	
                        end
								
						    4'd10,4'd11: begin
                            
									
                            ca_run   = 1'b1;

                        end

                        4'd2, 4'd3, 4'd4, 4'd5, 4'd6,
                        4'd7, 4'd8, 4'd9 : begin
                            phase_begin = 1'b0;
									 
                        end
								
                        4'd12: begin
                            phase_begin = 1'b0;
									 tag_load = 1'b1;
                            

                        end

                        4'd13: begin
                            tag_load = 1'b0;
                            //ca_run   = 1'b0;
                            stop     = 1'b1;
                        end

                        default: begin
                            phase_begin = 1'b0;
                        end
                    endcase
                end

                default: begin
                    stop = 1'b0;
                end
            endcase
        end
    end

endmodule

///////////////////////////////////////////////////////////////////////////////////////
//////////      mux 2x1 32 bit input line module                            ///////////
///////////////////////////////////////////////////////////////////////////////////////
module mux2x1_64bit(inp1,inp2,ctrl_signal,out);
input [0:63]  inp1;
input [0:63]  inp2;
input  ctrl_signal;
output[0:63]  out;
assign out = ctrl_signal ? inp2 : inp1;
endmodule
///////////////////////////////////////////////////////////////////////////////////////
//////////      register 64 bit  module                                     ///////////
///////////////////////////////////////////////////////////////////////////////////////
module pipo_64_bit_reg(clk,clear, pi, po);
input clk,clear;
input  [0:63] pi;
output [0:63] po;
wire   [0:63] pi;
reg    [0:63] po;
always @(posedge clk)
begin
if (clear)
po<= 64'h0000000000000000;
else
po <= pi;
end
endmodule
///////////////////////////////////////////////////////////////////////////////////////
//////////      register 64 bit  module                                     ///////////
///////////////////////////////////////////////////////////////////////////////////////
module ascon_sbox(
    input [0:4] a,
    output [0:4] b
    );
 wire y0,y1,y2,y3,y4;

 assign y0 = a[4]&a[1] ^ a[3]^ a[2]&a[1] ^ a[2] ^ a[1]&a[0] ^ a[1] ^a[0];
 assign y1 = a[4]^ a[2]&a[3]^ a[3]^ a[3]&a[1]^ a[2]^ a[1]&a[2]^ a[1] ^ a[0];
 assign y2 = a[4]&a[3] ^ a[4] ^ a[2] ^ a[1] ^ 1'b1;
 assign y3 = a[4]&a[0] ^ a[3]&a[0] ^ a[4]^ a[3]^ a[2] ^ a[1] ^ a[0] ;
 assign y4 = a[4]&a[1] ^ a[4] ^ a[3] ^ a[1]&a[0] ^ a[1]; 

 assign b ={y0,y1,y2,y3,y4};
endmodule
///////////////////////////////////////////////////////////////////////////////////////
//////////      register 64 bit  module                                     ///////////
///////////////////////////////////////////////////////////////////////////////////////
module mlca_5bit (
    input  wire       clk,
    input  wire       rst,
    input  wire [4:0] seed,
    output reg  [4:0] ca_state
);

wire [4:0] next_state;

// Rule Vector: [90, 90, 90, 90, 150]
// Null Boundary

assign next_state[0] = ca_state[0] ^ ca_state[1];   // Rule 150
assign next_state[1] = ca_state[0] ^ ca_state[2];   // Rule 90
assign next_state[2] = ca_state[1] ^ ca_state[3];   // Rule 90
assign next_state[3] = ca_state[2] ^ ca_state[4];   // Rule 90
assign next_state[4] = ca_state[3];                 // Rule 90

always @(posedge clk) begin
    if (rst)
        ca_state <=  seed;
    else
        ca_state <= next_state;
end

endmodule
