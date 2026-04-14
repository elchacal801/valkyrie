# Accuracy Self-Assessment: TEST-001

## Overall Assessment

**Investigation Quality**: HIGH
**Self-Correction Effectiveness**: HIGH (2 in-flight reclassifications, 0 post-hoc corrections)
**Evidence Coverage**: LIMITED (memory-only, 1 of 6 techniques applicable)

---

## What Went Well

1. **Accurate process chain reconstruction**: The WMI → PowerShell → rundll32 attack chain was correctly identified from psscan data alone, despite pslist failure.
2. **Shellcode extraction**: Raw strings analysis recovered the complete Cobalt Strike reflective loader code, including the named pipe C2 channel identifier.
3. **In-flight self-correction**: subject_srv.exe (F-Response) and 172.16.4.10 (corporate proxy) were correctly reclassified during analysis, preventing false positives in the final report.
4. **Hypothesis rigor**: 5 hypotheses evaluated via ACH, including genuine consideration of the null hypothesis (legitimate activity) and red team scenario.
5. **Tool adaptation**: When 7 Volatility3 plugins failed, the investigation pivoted to pool-scanning plugins and raw strings extraction without losing analytical depth.

## What Could Be Improved

1. **Volatility3 ISF symbols**: The correct symbol table for this Windows 7 SP1 build should be downloaded to enable pslist, cmdline, malfind, and dlllist. This would provide:
   - Command lines for all PowerShell instances (cmdline)
   - Injected memory regions with disassembly (malfind)
   - Loaded DLLs for subject_srv.exe and rundll32 instances (dlllist)
   - Handle analysis for named pipe connections (handles)

2. **Shellcode analysis depth**: The base64-encoded shellcode was identified but not fully disassembled. A dedicated shellcode emulator (e.g., scdbg or speakeasy) could extract the exact C2 configuration, including sleep interval, watermark, and additional pipe names.

3. **FLOSS not used**: The newly installed FLOSS tool was not applied to extract obfuscated strings from the shellcode payload. This should be done on extracted process memory dumps.

4. **No MCP server used**: The investigation used Volatility3 and strings directly via Bash rather than through the VALKYRIE MCP server. The MCP tools would provide structured JSON output and automatic audit logging.

## Confidence Assessment by Finding

| Finding | Self-Assessed Confidence | Rationale |
|---------|------------------------|-----------|
| F-001 | HIGH — appropriate | Shellcode extracted from memory, PIDs verified, named pipe identified. Multiple independent evidence lines. |
| F-002 | HIGH — appropriate | 5 rundll32 instances verified in psscan with consistent parent PID and timestamps. |
| F-003 | MEDIUM — appropriate | PID verified but orphan status could have benign explanation (parent simply exited). MEDIUM is correct. |
| F-004 | MEDIUM — appropriate | Inference based on co-existence of AV processes and attack artifacts. Cannot prove AV "failed" vs "was bypassed." |
| HT-001 | HIGH — borderline | ACH conclusion is Tier 3 inference. HIGH confidence is justified by zero-inconsistency result, but a stricter standard would cap Tier 3 at MEDIUM. |

## Suggested Next Steps for Full Investigation

1. Download correct ISF symbols and re-run malfind + cmdline + dlllist
2. Dump process memory for PIDs 1124, 1332, 4072, 7100 and run FLOSS on each
3. Analyze memory dumps from other SRL-2018 workstations for the same named pipe IOC
4. Extract and analyze disk images for timeline reconstruction and persistence enumeration
5. Run the full VALKYRIE guided pipeline with disk + memory evidence
