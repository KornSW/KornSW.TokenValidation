using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Security.AccessTokenHandling {

  public class DefaultAccessTokenValidator {

    private DefaultAccessTokenValidator() {
    }

    public static IAccessTokenValidator Instance { get; set; } = null;

  }

}
