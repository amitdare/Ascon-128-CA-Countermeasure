//`default_nettype none
`timescale 1ns / 1ps

////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer:
//
// Create Date:   18:33:44 07/28/2026
// Design Name:   Ascon_128
// Module Name:   D:/Ascon_128/test.v
// Project Name:  Ascon_128
// Target Device:  
// Tool versions:  
// Description: 
//
// Verilog Test Fixture created by ISE for module: Ascon_128
//
// Dependencies:
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
////////////////////////////////////////////////////////////////////////////////

module test;

	// Inputs
	reg clk;
	reg rst;
	reg start;
   reg [0:127] key;
	reg [0:63] AD;
	reg [0:63] pT;
	reg [0:63] initial_value;
	reg [0:127] nonce;
	// Outputs
	/*
	wire [0:63]  x0;
	wire [0:63]  x1;
	wire [0:63]  x2;
	wire [0:63]  x3;
	wire [0:63]  x4;
	*/
	
	wire [1:0] phase;
	wire [3:0] state;
	wire [1:0] ad_counter;
	wire [1:0] pt_counter;
	wire start_ip;
	wire start_ad;
	wire start_pt;
	wire start_fp;
	/*wire state1_f;
	wire set7;
	wire set1;
	wire ad_counter_decrease;
	wire pt_counter_decrease;
	wire trans_phase;
	wire ad_to_pt_transition;
	*/
	wire ct_load;
	wire tag_load;
	wire ca_run;
	wire busy;
	wire stop;
   /*wire [0:63]  mux4x2_out1,mux4x2_out2,mux4x2_out3,mux4x2_out4,mux4x2_out5;
	wire [0:63]  x2_temp,xor_ad_pt;
	wire [0:63] after_sb_x0,after_sb_x1,after_sb_x2,after_sb_x3,after_sb_x4;
	wire [0:7]  intermediate_value,intermediate_value_f;
	*/
	wire [0:63] ciphertext;
	//wire key0_xor;
	//wire key1_xor;
   wire  [0:63]  Tag0;
	wire  [0:63]  Tag1;
	//wire  [0:63]      Tag0_t;
	//wire  [0:63]      Tag1_t;
   //wire  [0:63] after_lr_x0,after_lr_x1,after_lr_x2,after_lr_x3,after_lr_x4;
	//wire  [0:63] after_lr_x0_ca,after_lr_x1_ca,after_lr_x2_ca,after_lr_x3_ca,after_lr_x4_ca;
	//wire [4:0] ca_state;
    wire              set7;
	 wire              set1;
	 wire 				 key0_xor;
	 wire        		 key1_xor;
	 wire          	 ad_counter_decrease;
	 wire          	 pt_counter_decrease;
	 wire          	 AP_to_PP_trans;
    wire          	 PP_to_FP_trans;
	// Instantiate the Unit Under Test (UUT)
	Ascon_128 uut (
		.clk(clk), 
		.rst(rst), 
		.start(start), 
		.key(key), 
		.AD(AD), 
		.pT(pT),
		.initial_value(initial_value),
      .nonce(nonce),	
		/*
		.x0(x0), 
		.x1(x1), 
		.x2(x2), 
		.x3(x3),
		.x4(x4),	
*/		
		.phase(phase), 
		.state(state), 
		.ad_counter(ad_counter), 
		.pt_counter(pt_counter), 
		.start_ip(start_ip), 
		.start_ad(start_ad), 
		.start_pt(start_pt), 
		.start_fp(start_fp), 
		/*.state1(state1_f), 
		.set7(set7), 
		.set1(set1), 
		.ad_counter_decrease(ad_counter_decrease), 
		.pt_counter_decrease(pt_counter_decrease), 
		.trans_phase(trans_phase), 
		.ad_to_pt_transition(ad_to_pt_transition), 
		*/
		.ct_load(ct_load), 
		.tag_load(tag_load), 
		.ca_run(ca_run), 
		.busy(busy), 
		.stop(stop),
		/*
		.mux4x2_out1(mux4x2_out1),
		.mux4x2_out2(mux4x2_out2),
		.mux4x2_out3(mux4x2_out3),
		.mux4x2_out4(mux4x2_out4),
		.mux4x2_out5(mux4x2_out5),
		.x2_temp(x2_temp),
		.xor_ad_pt(xor_ad_pt),
		.after_sb_x0(after_sb_x0),
		.after_sb_x1(after_sb_x1),
		.after_sb_x2(after_sb_x2),
		.after_sb_x3(after_sb_x3),
		.after_sb_x4(after_sb_x4),
		.intermediate_value(intermediate_value),
		.intermediate_value_f(intermediate_value_f),
		*/
		.ciphertext(ciphertext),
		//.key0_xor(key0_xor),
		//.key1_xor(key1_xor),
		.Tag0(Tag0),
		.Tag1(Tag1),
		//.Tag0_t(Tag0_t),
		//.Tag1_t(Tag1_t),
		/*.after_lr_x0(after_lr_x0),
		.after_lr_x1(after_lr_x1),
		.after_lr_x2(after_lr_x2),
		.after_lr_x3(after_lr_x3),
		.after_lr_x4(after_lr_x4),
		.after_lr_x0_ca(after_lr_x0_ca),
		.after_lr_x1_ca(after_lr_x1_ca),
		.after_lr_x2_ca(after_lr_x2_ca),
		.after_lr_x3_ca(after_lr_x3_ca),
		.after_lr_x4_ca(after_lr_x4_ca),
		*/
		//.ca_state(ca_state)
		.set7(set7),
		.set1(set1),
		.key0_xor(key0_xor),
		.key1_xor(key1_xor),
		.ad_counter_decrease(ad_counter_decrease),
		.pt_counter_decrease(pt_counter_decrease),
		.AP_to_PP_trans(AP_to_PP_trans),
		.PP_to_FP_trans(PP_to_FP_trans)
		
	);

	initial begin
		// Initialize Inputs
		clk = 0;
		rst = 0;
		start = 0;
		key = 128'h000102030405060708090A0B0C0D0E0F;
		AD = 64'h4153434f4e000000;
		pT = 64'h0000004153434f4e;
		        
		nonce = 128'h000102030405060708090A0B0C0D0E0F;
		initial_value = 64'h80400C0600000000;

		
		#10 
		rst = 1;
		#100
		rst = 0;
		start = 1;

		// Wait 100 ns for global reset to finish
		#100;
        
		// Add stimulus here

	end
 always 
    #5 clk = ~clk; 
endmodule

