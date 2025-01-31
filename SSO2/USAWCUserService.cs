
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Data.SqlClient;

namespace SSO2
{
    public static class USAWCUserService
    {
        public static Dictionary<string, USAWCUser> GetUSAWCUserDictionary(HttpContext context, IMemoryCache cache)
        {
            string CacheKey = "USAWCUsersDictionary";
            var configuration = context.RequestServices.GetRequiredService<IConfiguration>();

            if (cache.TryGetValue(CacheKey, out Dictionary<string, USAWCUser> cachedUsers))
            {
                return cachedUsers;
            }

            var users = new Dictionary<string, USAWCUser>(StringComparer.OrdinalIgnoreCase); // Case-insensitive keys

            var query = @"
        WITH e AS (
            SELECT 
                PersonID, 
                Email,
                CASE 
                    WHEN Email LIKE '%@army.mil' THEN 'army'
                    WHEN Email LIKE '%@armywarcollege.edu' THEN 'edu'
                END AS EmailType
            FROM [USAWCPersonnel].[Person].[Emails]
            WHERE Email LIKE '%@army.mil' OR Email LIKE '%@armywarcollege.edu'
        )
        SELECT 
            p.PersonID, 
            p.LastName, 
            p.FirstName, 
            p.MiddleName, 
            MAX(CASE WHEN e.EmailType = 'army' THEN e.Email END) AS ArmyEmail,
            MAX(CASE WHEN e.EmailType = 'edu' THEN e.Email END) AS EduEmail
        FROM [USAWCPersonnel].[Person].[Person] p
        JOIN e ON p.PersonID = e.PersonID
        JOIN Security.PersonRole pr ON pr.PersonID = e.PersonID
        WHERE p.IsActive = 1 
            AND (p.IsDeceased IS NULL OR p.IsDeceased = 0)
            AND pr.RoleID IN (1, 2, 5, 107)
        GROUP BY 
            p.PersonID, 
            p.LastName, 
            p.FirstName, 
            p.MiddleName
        HAVING 
            MAX(CASE WHEN e.EmailType = 'army' THEN e.Email END) IS NOT NULL
            OR MAX(CASE WHEN e.EmailType = 'edu' THEN e.Email END) IS NOT NULL";

            var connectionString = configuration.GetConnectionString("USAWCPersonnelConnection");

            using (var connection = new SqlConnection(connectionString))
            {
                connection.Open();

                using (var command = new SqlCommand(query, connection))
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var user = new USAWCUser
                        {
                            PersonId = reader.GetInt32(reader.GetOrdinal("PersonID")),
                            LastName = reader.GetString(reader.GetOrdinal("LastName")),
                            FirstName = reader.GetString(reader.GetOrdinal("FirstName")),
                            MiddleName = reader.IsDBNull(reader.GetOrdinal("MiddleName")) ? null : reader.GetString(reader.GetOrdinal("MiddleName")),
                            ArmyEmail = reader.IsDBNull(reader.GetOrdinal("ArmyEmail")) ? null : reader.GetString(reader.GetOrdinal("ArmyEmail")),
                            EduEmail = reader.IsDBNull(reader.GetOrdinal("EduEmail")) ? null : reader.GetString(reader.GetOrdinal("EduEmail")),
                        };

                        // 🔹 Add both Army and Edu emails to the dictionary for fast lookup
                        if (!string.IsNullOrEmpty(user.ArmyEmail))
                        {
                            users[user.ArmyEmail] = user;
                        }
                        if (!string.IsNullOrEmpty(user.EduEmail))
                        {
                            users[user.EduEmail] = user;
                        }
                    }
                }
            }

            // 🔹 Store in cache for future requests
            cache.Set(CacheKey, users, TimeSpan.FromHours(24));

            return users;
        }

    }
}
