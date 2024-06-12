using IntegrationLib;
using ServerService;
using SharedLib.Dispatcher;
using System.Data.Entity;

namespace AuthPlugin
{
    public sealed class AuthPlugin : GizmoServiceAuthPluginBase
    {
        public override AuthResult Authenticate(IDictionary<string, object> authHeaders, IMessageDispatcher dispatcher)
        {
            //check if required header kyes are set
            if (!authHeaders.ContainsKey("USERNAME") || !authHeaders.ContainsKey("PASSWORD"))
                return new AuthResult(LoginResult.InvalidParameters);

            //try to obtain username and password values
            authHeaders.TryGetValue("USERNAME", out var username);
            authHeaders.TryGetValue("PASSWORD", out var password);

            //check if both passwords are not null and contains some value
            if (string.IsNullOrWhiteSpace(username?.ToString()) || string.IsNullOrWhiteSpace(password?.ToString()))
                return new AuthResult(LoginResult.InvalidCredentials);


            using (var httpClient = GetHttpClient())
            {

            }

            //try to get existing or create a new user, if the function returns null then we cant proceed since 
            //we could not create a local user
            var localUserEntity = GetOrCreateLocalUser(username.ToString()!);
            if (localUserEntity == null)
                return new AuthResult(LoginResult.Failed);           

            var userIdentity = new ClaimsUserIdentity(localUserEntity.Username, localUserEntity.Id, Gizmo.UserRoles.User);

            return new AuthResult(LoginResult.Sucess, userIdentity);
        }

        public override void PostAuthenticate(AuthResult result, IMessageDispatcher dispatcher)
        {
            //we don't want to do any extra handling here
        }

        /// <summary>
        /// Creates an Http client initialized and suitable of making authentication api requests.
        /// </summary>
        /// <returns>Http client.</returns>
        private HttpClient GetHttpClient()
        {
            return new HttpClient();
        }

        private Gizmo.DAL.Entities.UserMember? GetOrCreateLocalUser(string userName)
        {
            try
            {
                using (var dbContext = Service.GetDbNonProxyContext())
                {
                    var userDbSet = (DbSet<Gizmo.DAL.Entities.UserMember>)dbContext.QueryableSet<Gizmo.DAL.Entities.UserMember>();
                    var userGroupDbSet = (DbSet<Gizmo.DAL.Entities.UserGroup>)dbContext.QueryableSet<Gizmo.DAL.Entities.UserGroup>();

                    using (var trx = dbContext.BeginTransaction(System.Data.IsolationLevel.Serializable))
                    {
                        //try to find local user by comparing the username
                        var currentUser = userDbSet.Where(userMember => userMember.Username.ToLower() == userName.ToLower()).FirstOrDefault();

                        if (currentUser == null)
                        {
                            //we did not find an user match 
                            //we will create a new local user
                            //we will require an user group id since it is required for any user

                            var defaultUserGroupId = userGroupDbSet.Where(userGroup => userGroup.IsDefault).Select(userGroup => (int?)userGroup.Id).FirstOrDefault();
                            if (defaultUserGroupId == null)
                            {
                                //no default user group is configured
                                //try to get any user group and use it for the new user
                                defaultUserGroupId = userGroupDbSet.Select(userGroup => (int?)userGroup.Id).FirstOrDefault();
                            }

                            if (defaultUserGroupId == null)
                            {
                                //there are no user groups configured in the system, this will not allow us to create new user
                                return null;
                            }

                            //create new user
                            currentUser = new Gizmo.DAL.Entities.UserMember()
                            {
                                Username = userName,
                                UserGroupId = defaultUserGroupId.Value,
                            };

                            userDbSet.Add(currentUser);
                        }

                        //save changes
                        dbContext.SaveChanges();

                        //commit any changes made
                        trx.Commit();

                        //return local user entity
                        return currentUser;
                    }
                }
            }
            catch
            {
                //here we can only log the error, nothing else can be done
                return null; 
            }
        }

        public override void OnImportsSatisfied()
        {
            base.OnImportsSatisfied();
        }
    }
}
