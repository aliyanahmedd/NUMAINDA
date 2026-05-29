"""Social Media Intelligence Agent - GitHub search for company presence."""
from utils.api_client import github_search_users, github_user_repos
from utils.helpers import log_info, log_success, log_warn


class SocialAgent:
    def run(self, domain: str) -> dict:
        company = domain.split(".")[0]
        log_info(f"[SocialAgent] Searching GitHub for: {company}")
        results = {"github_users": [], "repositories": []}

        user_data = github_search_users(f"{company} in:login,name,company")
        if not user_data:
            log_warn("[SocialAgent] GitHub user search returned no results")
            return results

        users = user_data.get("items", [])[:5]
        log_success(f"[SocialAgent] Found {len(users)} GitHub users matching {company}")

        for user in users:
            username = user["login"]
            repos = github_user_repos(username) or []
            results["github_users"].append({
                "username": username,
                "profile_url": user.get("html_url"),
                "public_repos": user.get("public_repos"),
                "followers": user.get("followers"),
            })
            for repo in repos[:5]:
                results["repositories"].append({
                    "owner": username,
                    "name": repo["name"],
                    "description": repo.get("description", ""),
                    "language": repo.get("language", ""),
                    "stars": repo.get("stargazers_count", 0),
                    "url": repo.get("html_url", ""),
                    "topics": repo.get("topics", []),
                })

        return results
