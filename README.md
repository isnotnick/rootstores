# rootstores
Compile PEM-formatted trust stores from Apple, Microsoft and Mozilla

Fetches the trusted roots from the major trust stores. Output is a concatenated PEM of the individual certificates.

Rather hacky in all cases, but functional.

### Notes
* Apple - crawls from Apple's Open Source pages, so may need updating manually as they do.
* Mozilla - fetches certificates from the Mercurial repo, and grabs only the 'trusted' certs for serverAuth.
* Microsoft - rather than grabbing the authroot.stl files from Microsoft directly, cheat and get the already-nicely-formatted versions from Rob (Stradling's) repo where he does all the work for us.
* Google - now Chromium/Google have their own store, maintain a separate one for it.
