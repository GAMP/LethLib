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
            //check if required header keys are set
            if (!authHeaders.ContainsKey("USERNAME") || !authHeaders.ContainsKey("PASSWORD"))
                return new AuthResult(LoginResult.InvalidParameters);

            //try to obtain username and password values
            authHeaders.TryGetValue("USERNAME", out var username);
            authHeaders.TryGetValue("PASSWORD", out var password);

            //the keys might have been present in the auth headers but the value object might have null values

            //check if both passwords are not null and contains some value
            if (string.IsNullOrWhiteSpace(username?.ToString()) || string.IsNullOrWhiteSpace(password?.ToString()))
                return new AuthResult(LoginResult.InvalidCredentials);

            //block user names with white spaces, this is only to protect us from username with white spaces coming from your own api
            //TODO : other checks might also be needed such as illegal characters and such
            if (username.ToString()!.ToCharArray().Any(c => char.IsWhiteSpace(c)))
                return new AuthResult(LoginResult.InvalidParameters);

            using (var httpClient = GetHttpClient())
            {
                //make an external api call and determine if user credentials are correct
            }

            //try to get existing or create a new user, if the function returns null then we cant proceed since we could not create a local user

            //NOTE : this function could receive more parameters such as user info First,Last names e.t.c
            //those values could be used to update local user or used when creating a new one
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

        /// <summary>
        /// Gets or creates user with specified username.
        /// </summary>
        /// <param name="username">Username.</param>
        /// <returns>User entity or null in case of error.</returns>
        private Gizmo.DAL.Entities.UserMember? GetOrCreateLocalUser(string username)
        {
            try
            {
                using (var dbContext = Service.GetDbNonProxyContext())
                {
                    var userDbSet = (DbSet<Gizmo.DAL.Entities.UserMember>)dbContext.QueryableSet<Gizmo.DAL.Entities.UserMember>();
                    var userGroupDbSet = (DbSet<Gizmo.DAL.Entities.UserGroup>)dbContext.QueryableSet<Gizmo.DAL.Entities.UserGroup>();

                    //database transaction might be overkill here, it can be removed. The goal is to ensure no two users being created with same username at same time BUT it might not be a problem
                    //since it wont be allowed on the database level so the only potential outcome is one of the users getting an login error once.
                    using (var trx = dbContext.BeginTransaction(System.Data.IsolationLevel.Serializable))
                    {
                        //try to find local user by comparing the username
                        var currentUser = userDbSet.Where(userMember => userMember.Username.ToLower() == username.ToLower()).FirstOrDefault();

                        //if we failed to find a local user with specified username then we need to create a new one
                        if (currentUser == null)
                        {
                            //we will need an user group id since it is required for any user

                            //get the user group that is marked as default
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
                                Username = username,
                                UserGroupId = defaultUserGroupId.Value,
                            };

                            //add the new user to db set, EF will pick that up and save it to database upon SaveChanges.
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
