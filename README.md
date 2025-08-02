# tl;dr
Make sure your laptop never blasts your music when you unlock it.

Mutes your audio playback devices when you logon, logoff, lock, or unlock your computer. (via the Windows Event Log). 
# Requirements

* Windows (not cross platform)
* Rust 1.80+
* Windows Event Logon Auditing:  
  Auditing of Logon events must be enabled. See also: [Microsoft MSDN](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd772704(v=ws.10)), [StackOverflow](https://stackoverflow.com/questions/11385164/eventviewer-eventid-for-lock-and-unlock#:%7E:text=The%20lock%20event%20ID%20is,Local%20Policies%20%2D%3E%20Audit%20Policy)

    as a summary:  
    
        Events 4800 and 4801 are not audited by default, and must be enabled using either Local Group Policy Editor (gpedit.msc) or Local Security Policy (secpol.msc).

        The path for the policy using Local Group Policy Editor is:

            Local Computer Policy
            Computer Configuration
            Windows Settings
            Security Settings
            Advanced Audit Policy Configuration
            System Audit Policies - Local Group Policy Object
            Logon/Logoff
            Audit Other Logon/Logoff Events

        The path for the policy using Local Security Policy is the following subset of the path for Local Group Policy Editor:

            Security Settings
            Advanced Audit Policy Configuration
            System Audit Policies - Local Group Policy Object
            Logon/Logoff
            Audit Other Logon/Logoff Events

