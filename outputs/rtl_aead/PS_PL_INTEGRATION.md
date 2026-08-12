# ZedBoard PS-PL integration steps

## Vivado block design

1. Add every SystemVerilog file under `rtl/` to the project.
2. Package `mlkem_secure_channel_complete_axi_top` as the custom peripheral.
3. Create a block design containing `ZYNQ7 Processing System`.
4. Run PS block automation for DDR and FIXED_IO.
5. Enable `M_AXI_GP0` and `FCLK_CLK0` in the PS configuration.
6. Connect `M_AXI_GP0` through AXI Interconnect/SmartConnect to both AXI-Lite
   slave interfaces of the peripheral.
7. Drive `s_axi_aclk` from `FCLK_CLK0` and use a Processor System Reset block
   for `s_axi_aresetn`.
8. Example addresses: ML-KEM load/control `0x43C00000`, AEAD traffic
   `0x43C10000`.
9. Generate the HDL wrapper and bitstream, then export the XSA to Vitis.

The final address generated in `xparameters.h` must replace the fallback
address in `ps_driver/example_baremetal.c`.

## Vitis application

Add these files to a bare-metal application:

```text
ps_driver/aead_hw.h
ps_driver/aead_hw.c
ps_driver/mlkem_decaps_hw.h
ps_driver/mlkem_decaps_hw.c
ps_driver/secure_channel_hw.h
ps_driver/secure_channel_hw.c
```

Call `secure_channel_hw_load_secret_key` once, followed by
`secure_channel_hw_establish_session` for each accepted ML-KEM ciphertext.
PL performs Decaps, transcript hashing, direction-separated KDF and atomic
session installation. Ethernet software can then call
`secure_channel_hw_encrypt` or `secure_channel_hw_decrypt` one at a time.

## Current transfer method

The secret key, ML-KEM ciphertext and 64-byte traffic area are transferred as
32-bit AXI4-Lite accesses.
There is no DMA and no PL request FIFO in this version. Software must wait for
the current request to finish before submitting another request.
