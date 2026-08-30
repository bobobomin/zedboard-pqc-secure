`timescale 1ns/1ps

/* Complete FIPS 203 ML-KEM-512 Decaps datapath over external SK/CT/POLY BRAM. */
module mlkem512_decaps_engine(
    input logic clk_i,input logic rst_ni,input logic start_i,
    output logic busy_o,output logic done_o,output logic fail_o,
    output logic[255:0]shared_secret_o,
    output logic sk_we_o,output logic[8:0]sk_addr_o,output logic[31:0]sk_wdata_o,
    input logic[31:0]sk_rdata_i,
    output logic ct_we_o,output logic[7:0]ct_addr_o,output logic[31:0]ct_wdata_o,
    input logic[31:0]ct_rdata_i,
    output logic poly_we_o,output logic[11:0]poly_addr_o,
    output logic[15:0]poly_wdata_o,input logic[15:0]poly_rdata_i);
    typedef enum logic[4:0]{IDLE,D_S,D_W,U_S,U_W,H_S,H_W,G_S,G_W,
        E_S,E_W,J_S,J_W,SELECT,DONE}st_t;st_t state;
    logic ds,dd,dwe,doperr;logic[7:0]dcta;logic[8:0]dska;logic[11:0]dpa;logic[15:0]dpd;logic[255:0]msg;
    logic us,ud,uwe;logic[8:0]uska;logic[11:0]upa;logic[15:0]upd;logic[255:0]rho,hpk,z;
    logic hs,hd;logic[8:0]hska;logic[255:0]hcalc;
    logic gs,gd;logic[511:0]gdigest;
    logic es,ed,emis,ewe;logic[7:0]ecta;logic[11:0]epa;logic[15:0]epd;
    logic js,jd;logic[7:0]jcta;logic[255:0]jdigest;logic fail_q;
    mlkem512_kpke_decrypt_engine dec(.clk_i(clk_i),.rst_ni(rst_ni),.start_i(ds),
        .busy_o(),.done_o(dd),.message_o(msg),.ct_addr_o(dcta),.ct_rdata_i(ct_rdata_i),
        .sk_addr_o(dska),.sk_rdata_i(sk_rdata_i),.poly_we_o(dwe),.poly_addr_o(dpa),
        .poly_wdata_o(dpd),.poly_rdata_i(poly_rdata_i),.operation_fault_o(doperr));
    mlkem512_unpack_public_controller unpack_pk(clk_i,rst_ni,us,,ud,uska,sk_rdata_i,
        uwe,upa,upd,rho,hpk,z);
    mlkem512_public_key_hash hash_pk(clk_i,rst_ni,hs,,hd,hcalc,hska,sk_rdata_i);
    mlkem_hash_g hash_g(clk_i,rst_ni,gs,{hpk,msg},,gd,gdigest);
    mlkem512_kpke_reencrypt_engine enc(clk_i,rst_ni,es,msg,rho,gdigest[511:256],,
        ed,emis,ecta,ct_rdata_i,ewe,epa,epd,poly_rdata_i);
    mlkem512_rejection_hash hash_j(clk_i,rst_ni,js,z,,jd,jdigest,jcta,ct_rdata_i);
    always_comb begin
        ds=state==D_S;us=state==U_S;hs=state==H_S;gs=state==G_S;
        es=state==E_S;js=state==J_S;
        sk_we_o=0;sk_wdata_o=0;ct_we_o=0;ct_wdata_o=0;
        if(state==D_S||state==D_W)begin sk_addr_o=dska;ct_addr_o=dcta;
            poly_we_o=dwe;poly_addr_o=dpa;poly_wdata_o=dpd;end
        else if(state==U_S||state==U_W)begin sk_addr_o=uska;ct_addr_o=0;
            poly_we_o=uwe;poly_addr_o=upa;poly_wdata_o=upd;end
        else if(state==H_S||state==H_W)begin sk_addr_o=hska;ct_addr_o=0;
            poly_we_o=0;poly_addr_o=0;poly_wdata_o=0;end
        else if(state==E_S||state==E_W)begin sk_addr_o=0;ct_addr_o=ecta;
            poly_we_o=ewe;poly_addr_o=epa;poly_wdata_o=epd;end
        else begin sk_addr_o=0;ct_addr_o=jcta;poly_we_o=0;poly_addr_o=0;poly_wdata_o=0;end
        busy_o=state!=IDLE;done_o=state==DONE;fail_o=fail_q;
    end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;fail_q<=0;shared_secret_o<=0;end else case(state)
            IDLE:if(start_i)begin fail_q<=0;shared_secret_o<=0;state<=D_S;end
            D_S:state<=D_W;D_W:if(dd)begin fail_q<=doperr;state<=U_S;end
            U_S:state<=U_W;U_W:if(ud)state<=H_S;
            H_S:state<=H_W;H_W:if(hd)begin fail_q<=fail_q|(hcalc!=hpk);state<=G_S;end
            G_S:state<=G_W;G_W:if(gd)state<=E_S;
            E_S:state<=E_W;E_W:if(ed)begin fail_q<=fail_q|emis;state<=J_S;end
            J_S:state<=J_W;J_W:if(jd)state<=SELECT;
            SELECT:begin shared_secret_o<=fail_q?jdigest:gdigest[255:0];state<=DONE;end
            DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule
