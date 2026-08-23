# collectors/

One module per Guardian, each implementing the `BaseGuardian` interface
defined in `base.py` (Phase 3). Collectors gather raw system facts only —
no severity judgment or scoring happens here; that lives server-side in
`dashboard/app/modules/`.

Populated in Phases 8–16:
- permission_guardian.py
- ownership_guardian.py
- ssh_guardian.py
- sudo_guardian.py
- cron_guardian.py
- secret_guardian.py
- docker_guardian.py
- firewall_guardian.py
- kernel_guardian.py
