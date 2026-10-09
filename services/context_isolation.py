"""Trusted/untrusted context separation for LLM-bound inputs."""

class ContextIsolation:
    def isolate(self, user_input=None, external_content=None, trusted_context=None,
                source=None, source_type=None):
        trusted = list(trusted_context or [])
        user = [user_input] if user_input else []
        external = []
        for item in external_content or []:
            if isinstance(item, dict):
                external.append({
                    "content": str(item.get("content", "")),
                    "source": item.get("source") or source or "unknown",
                    "source_type": item.get("source_type") or source_type or "external",
                    "trust_level": "untrusted",
                })
            else:
                external.append({"content": str(item), "source": source or "unknown",
                                 "source_type": source_type or "external", "trust_level": "untrusted"})
        wrapped_user = ["<UNTRUSTED_USER_INPUT>\n" + str(user_input) + "\n</UNTRUSTED_USER_INPUT>"] if user_input else []
        wrapped_external = [
            "<UNTRUSTED_EXTERNAL_CONTENT>\n" + x["content"] + "\n</UNTRUSTED_EXTERNAL_CONTENT>" for x in external
        ]
        return {
            "trusted_context": trusted,
            "untrusted_context": wrapped_user + wrapped_external,
            "user_input": user,
            "external_content": external,
            "separation_enforced": True,
            "provenance": [{"source": x["source"], "source_type": x["source_type"], "trust_level": "untrusted"} for x in external],
        }
