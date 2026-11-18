# Security policy

## Reporting a problem

Report a security problem privately, through GitHub's "Report a vulnerability" button on the Security tab of
this repository. Please do not open a public issue for it.

Include the server version (`Version` in `src/WinDbgMCP.Server/WinDbgMCP.Server.csproj`), the Windows build of
the host, the version of Debugging Tools for Windows, and the steps that show the problem.

## In scope

- A tool argument that makes the server start a host program, load a DLL, read or write a host file outside
  `Policy.HostTransferRoots`, or open a network connection to a machine other than the configured guest.
- A debugger command that the host command filter (`Policy.BlockHostSideEffectCommands`) should refuse but
  lets through.
- A secret from the configuration (the KDNET key, `Guest.FridaToken`, `Guest.DbgsrvPassword`) in the server
  instructions, a tool result or a log line.
- A program started by the server from a location other than the one the README names.

## Out of scope

- What the guest account can do inside the guest. The server gives the model administrator control of one
  guest on purpose.
- What the host tasks of hyperv-lpe-lab allow. Report those to that repository.
- Anything that already needs administrator rights on the host, or code that already runs as the server's
  account.
- The limits of the host command filter that the README already states.
