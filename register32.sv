// 32-bit register

module register32(
        input logic Clk, Reset, Load,
        input logic [32:0] D,
        output logic [32:0] Data_Out);
	
	logic [32:0] out;
	
    always_ff @(posedge Clk) 
	 begin
        if (Reset)
			begin
            out <= 32'h0;
			end
        else if (Load)
			begin
            out <= D;
			end
        else
            out <= out;
    end

	 assign Data_Out = out;
	 
endmodule
