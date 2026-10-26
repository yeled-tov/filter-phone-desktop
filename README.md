# FilterPhone Desktop

Windows 10/11 starter project for the desktop edition of FilterPhone.

**Important:** this first build is an installer/UI prototype. It does not yet filter network traffic and must not be used as protection. The existing Android server/API cannot be assumed to provision a Windows VPN tunnel automatically. The Windows VPN provisioning, firewall enforcement, server-side device registration, and image-filtering integration must be implemented and tested before a filtering release.

## Build without compiling on your PC

1. Open the **Actions** tab in this repository.
2. Select **Build FilterPhone Desktop for Windows**.
3. Click **Run workflow**.
4. When the workflow completes, open its run and download the `FilterPhone-Desktop-Windows` artifact.
5. The artifact contains the Windows installer EXE.

The workflow builds on a GitHub-hosted Windows runner. No local development setup is required.

## Current starter scope

- Simple Windows desktop setup/status window.
- Windows 10/11 x64 packaging pipeline.
- GitHub Actions build producing an EXE installer.
- Clear prototype status so users are not misled into thinking filtering is active.

## Before any real filtering release

- Implement secure Windows device enrollment against the FilterPhone API.
- Issue a unique WireGuard configuration per PC; never embed a shared private key in the installer.
- Install/manage WireGuard and configure a persistent tunnel.
- Enforce a fail-closed firewall policy that prevents direct internet access when the tunnel is down, with a safe recovery path.
- Connect DNS filtering and the server-side image filtering proxy.
- Decide and test browser coverage, HTTPS trust requirements, certificate-pinned apps, and privacy disclosures.
- Sign the application and installer, add secure signed updates, and test on clean Windows 10 and Windows 11 machines.

Do not describe the prototype as secure, unremovable, or actively filtering.
