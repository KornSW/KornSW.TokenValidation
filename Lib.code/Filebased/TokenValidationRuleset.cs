using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Security.AccessTokenHandling {

  public class TokenValidationRuleset {

    public SubjectProfileConfigurationEntry[] SubjectProfiles { get; set; }
    public string JwtSignKey { get; set; }
    public string[] JwtAllowedIssuers { get; set; }

    public bool ApplyApiPermissionsFromJwtScope { get; set; }
    public bool ApplyDataAccessClearancesFromJwtScope { get; set; }

  }

  public class SubjectProfileConfigurationEntry {

    public string SubjectName { get; set; }

    public string SubjectTitle { get; set; } = "";

    public bool Disabled { get; set; } = false;

    public String[] AllowedHosts { get; set; }

    public String[] DefaultApiPermissions { get; set; }

    public Dictionary<String, String> DefaultDataAccessClearances { get; set; }

  }

}
