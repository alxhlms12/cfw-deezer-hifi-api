Deezer HiFi API

A Cloudflare Worker that wraps Deezer catalog, metadata, lyrics, radio, and playback functionality behind a simple HTTP API.

> [!WARNING]
> **AI-generated documentation:** This documentation and the Worker code were generated with AI assistance. They may contain mistakes, become outdated, or stop matching Deezer or Cloudflare behavior.
>
> If you encounter a problem while using this project, please open a **GitHub Issue** in the repository where you found it. Include the endpoint you called, the HTTP status, a sanitized error response, and relevant Worker logs.
>
> **Never post your ARL or any other secret in an issue.**

---

## 1. What this Worker does

The Worker exposes a HiFi-API-style interface over Deezer.

It provides:

- Track metadata
- Track lookup by Deezer ID or ISRC
- Search
- Albums and album tracks
- Artists
- Playlists
- Artwork
- Lyrics
- Synchronized lyrics
- Radio
- Recommendations
- Charts
- Genres
- Similar artists
- Similar albums
- Deezer FLAC playback
- MP3 320 kbps playback
- MP3 128 kbps fallback
- Range-aware streaming
- Multiple ARL failover
- ARL health checks through `/ping`
- Cloudflare KV metadata caching

The Worker accepts:

GET
HEAD
OPTIONS

2. Requirements

You need:

A Cloudflare account
A Cloudflare Worker
The Deezer Worker source code
At least one valid Deezer ARL
A Cloudflare KV namespace
The KV namespace bound to the Worker as:
GENERAL_MUSIC_CACHE

KV is strongly recommended, although the Worker can still operate without it using short-lived Worker memory caching.

3. Environment variables
Required
DEEZER_ARL

Your primary Deezer ARL.

Example:

DEEZER_ARL=YOUR_ARL_HERE

Never put a real ARL in GitHub, screenshots, source code, or documentation.

Treat an ARL like a password/session credential.

Optional additional ARLs

The Worker supports up to 10 ARLs:

DEEZER_ARL
DEEZER_ARL_2
DEEZER_ARL_3
DEEZER_ARL_4
DEEZER_ARL_5
DEEZER_ARL_6
DEEZER_ARL_7
DEEZER_ARL_8
DEEZER_ARL_9
DEEZER_ARL_10

You do not need to configure all ten.

A single-account setup can simply use:

DEEZER_ARL=...

A failover setup could use:

DEEZER_ARL=...
DEEZER_ARL_2=...
DEEZER_ARL_3=...

The Worker can fail over between configured accounts when an account cannot authenticate or cannot obtain the requested playback format.

4. Cloudflare KV setup

The Worker uses one shared KV namespace:

GENERAL_MUSIC_CACHE

The same namespace can also be used by the Qobuz Worker.

Deezer cache keys use:

music:deezer:

Qobuz cache keys use:

music:qobuz:

This keeps the providers separated inside the same KV namespace.

Create the KV namespace

In the Cloudflare dashboard:

Open Workers & Pages
Open KV
Create a namespace
Give it a name such as:
GENERAL_MUSIC_CACHE
Bind it to the Worker

Open your Worker:

Go to Settings
Open Bindings
Add a KV Namespace
Set the binding name to exactly:
GENERAL_MUSIC_CACHE
Select the namespace you created
Deploy the Worker again

The Worker will then have:

env.GENERAL_MUSIC_CACHE

available.

5. What gets cached?

The KV cache is intended for relatively stable Deezer metadata.

Examples:

Track metadata
ISRC lookups
Album metadata
Artist metadata
Playlist metadata

The Worker does not intentionally store your ARLs in KV.

Playback URLs are also not treated as permanent metadata because Deezer playback URLs are time-sensitive.

6. Recommended Cloudflare configuration

For one Deezer account:

DEEZER_ARL = your ARL
GENERAL_MUSIC_CACHE = your KV namespace binding

For multiple accounts:

DEEZER_ARL   = primary ARL
DEEZER_ARL_2 = backup ARL
DEEZER_ARL_3 = another backup ARL
GENERAL_MUSIC_CACHE = shared KV namespace

Do not commit real credentials to a public repository.

Use Cloudflare's secret/environment-variable system.

7. Deploying

After adding the Worker and configuring the variables/binding, deploy it through Cloudflare.

Suppose Cloudflare gives your Worker this URL:

https://deezer-api.example.workers.dev

That becomes your API base URL.

Replace:

https://deezer-api.example.workers.dev

with your actual Worker URL in the examples below.

8. /

Returns API capability information.

GET /

Example:

https://deezer-api.example.workers.dev/

Useful for clients that want to discover what the Worker supports.

9. /info-api

Alias for /.

GET /info-api
10. /info

Returns rich track information.

You can identify a track by Deezer ID or ISRC.

By Deezer ID
GET /info?id=TRACK_ID

Example:

/info?id=3135556
By ISRC
GET /info?isrc=ISRC

Example:

/info?isrc=USRC17607839
11. /track

/track is the main rich playback endpoint.

It returns metadata together with playback information.

By ID
GET /track?id=TRACK_ID
By ISRC
GET /track?isrc=ISRC
By search
GET /track?q=Blinding%20Lights&artist=The%20Weeknd

The response can contain:

Track metadata
Artist metadata
Album metadata
Artwork
Lyrics-related metadata
Playback format
MIME type
Stream URL
Bitrate
Bit depth
Sampling rate
Duration
Playback diagnostics
12. Playback quality

The Worker supports:

Value	Result
flac	FLAC 16-bit / 44.1 kHz
lossless	FLAC 16-bit / 44.1 kHz
hifi	FLAC 16-bit / 44.1 kHz
320	MP3 320 kbps
320k	MP3 320 kbps
mp3_320	MP3 320 kbps
hq	MP3 320 kbps
128	MP3 128 kbps
128k	MP3 128 kbps
mp3_128	MP3 128 kbps
standard	MP3 128 kbps

Example:

/track?id=3135556&quality=flac

or:

/stream?id=3135556&quality=320
13. Default playback behavior

The normal playback path is lossless-first.

The Worker does not intentionally turn a failed FLAC request into an MP3 request immediately.

For automatic playback, it can try configured accounts at the requested quality first.

For example:

ARL #1 -> FLAC
ARL #2 -> FLAC

Only after the FLAC attempts fail can the Worker move to a lower-quality fallback path.

This is useful if you have multiple Deezer accounts and want lossless playback whenever possible.

14. /stream

Returns playback information.

By ID
GET /stream?id=TRACK_ID
By ISRC
GET /stream?isrc=ISRC
Select quality
GET /stream?id=TRACK_ID&quality=flac
15. Direct stream redirect

Add:

stream=1

Example:

GET /stream?id=3135556&quality=flac&stream=1

The Worker redirects the client to the resolved playback URL.

This is useful for players that can follow HTTP redirects.

16. Range requests

The playback path supports HTTP byte ranges.

This is important for:

Seeking
Browser media elements
Partial playback
Players that request chunks
Download managers

Example:

Range: bytes=0-1048575

The Worker handles the range while performing the required Deezer stream processing.

17. /search

General search endpoint.

GET /search?q=The%20Weeknd
Track search
/search?q=Blinding%20Lights&type=track
Album search
/search?q=After%20Hours&type=album
Artist search
/search?q=The%20Weeknd&type=artist
Playlist search
/search?q=Workout&type=playlist
18. Search aliases

The Worker accepts:

Parameter	Meaning
q	General search
s	Track/general search
a	Artist search
al	Album search
p	Playlist search
i	ISRC lookup

Examples:

/search?s=Blinding%20Lights
/search?a=The%20Weeknd
/search?al=After%20Hours
/search?p=Workout
/search?i=USRC17607839
19. Search pagination

Use:

limit
offset

Example:

/search?q=The%20Weeknd&type=track&limit=25&offset=25
20. Search ordering

You can pass:

order

Example:

/search?q=The%20Weeknd&type=track&order=RANKING

The accepted values ultimately depend on Deezer.

21. /album
GET /album?id=ALBUM_ID

Example:

/album?id=302127

Optional pagination:

/album?id=302127&limit=25&offset=0

The response can contain:

Album metadata
Artwork
Artist
Release information
Track list
Pagination
22. /artist
GET /artist?id=ARTIST_ID

The include parameter can request additional information.

Top tracks
/artist?id=ARTIST_ID&include=top
Albums
/artist?id=ARTIST_ID&include=albums
Radio
/artist?id=ARTIST_ID&include=radio
Related artists
/artist?id=ARTIST_ID&include=related
Everything
/artist?id=ARTIST_ID&include=all
23. /playlist
GET /playlist?id=PLAYLIST_ID

Optional pagination:

/playlist?id=PLAYLIST_ID&limit=50&offset=0
24. /cover

Artwork lookup:

GET /cover?id=TRACK_ID

You can also search:

GET /cover?q=Blinding%20Lights

The response provides normalized artwork URLs.

25. /lyrics
GET /lyrics?id=TRACK_ID

The Worker can retrieve synchronized Deezer lyrics where available.

The lyric response can include:

Word-level synchronization
Line-level synchronization
LRC-style timing
Fallback lyric data

If synchronized lyrics are unavailable, the Worker can use its alternate lyric lookup path where available.

26. /recommendations
GET /recommendations?id=TRACK_ID

The Worker uses Deezer radio information to generate a recommendation list.

Example:

/recommendations?id=3135556&limit=20

This can be used to build an autoplay queue.

27. /radio
GET /radio?artist_id=ARTIST_ID

or:

/radio?id=ARTIST_ID

Pagination:

/radio?artist_id=ARTIST_ID&limit=25&offset=0
28. /artist/similar
GET /artist/similar?id=ARTIST_ID

Returns similar/related artists.

29. /album/similar
GET /album/similar?id=ALBUM_ID

This is a convenience route that generates album suggestions using the album's artist/catalog information.

It should not be interpreted as a guarantee that Deezer exposes a dedicated native "similar album" endpoint.

30. /chart
GET /chart

Optional genre:

/chart?genre=GENRE_ID

or:

/chart?genre_id=GENRE_ID

Pagination:

/chart?limit=25&offset=0
31. /genre
GET /genre

Specific genre:

GET /genre?id=GENRE_ID
32. /ping

/ping is the main account health-check endpoint.

GET /ping

The Worker checks each configured ARL individually.

The check can report:

Whether the ARL is configured
Whether authentication works
Whether the account can access playback
Whether FLAC playback is authorized
Which account slot was tested
Playback test information
Errors

Example:

{
  "slot": 1,
  "variable": "DEEZER_ARL",
  "status": "active",
  "can_lossless": true,
  "lossless_check": "flac_authorized"
}

The important distinction is:

valid ARL

does not necessarily mean:

lossless playback available

The Worker performs an actual FLAC authorization/playback probe.

33. Multiple ARL behavior

The Worker supports up to ten ARLs.

Playback can fail over between accounts when:

An ARL is expired
An ARL is invalid
Playback authentication fails
The requested quality cannot be obtained
Deezer rejects the playback request

The Worker keeps some playback/session state in memory.

This means memory caches are local to the current Worker isolate and are not permanent.

34. Cache architecture

There are several layers.

Worker memory

Used for short-lived:

Sessions
Playback state
Temporary metadata
Playback URL information
Cloudflare KV

Binding:

GENERAL_MUSIC_CACHE

Prefix:

music:deezer:

Used for stable metadata.

Playback URLs

Playback URLs should be considered short-lived.

Do not manually store them forever in your application database.

Resolve them again when necessary.

35. CORS

The Worker supports permissive CORS.

This makes it convenient for:

Web apps
PWAs
Flutter Web
Browser music players
Other HTTP clients

If you expose the Worker publicly, remember that anyone who can access it can consume the Deezer functionality available through your configured accounts.

36. Errors

Errors are returned as JSON where possible.

Example:

{
  "error": "Track not found",
  "status": 404,
  "provider": "deezer"
}

Common statuses:

Status	Meaning
200	Success
204	OPTIONS/CORS response
400	Invalid or missing parameter
404	Resource not found
405	HTTP method not supported
429	Upstream rate limit
500	Worker/configuration error
502	Upstream/provider failure
37. Quick-start examples
Search
https://YOUR-WORKER.workers.dev/search?q=Blinding%20Lights&type=track
Track by ISRC
https://YOUR-WORKER.workers.dev/track?isrc=USRC17607839
FLAC
https://YOUR-WORKER.workers.dev/stream?isrc=USRC17607839&quality=flac
Direct playback redirect
https://YOUR-WORKER.workers.dev/stream?isrc=USRC17607839&quality=flac&stream=1
Check all ARLs
https://YOUR-WORKER.workers.dev/ping
38. Recommended flow

For a music player:

ISRC
  ↓
/track?isrc=...
  ↓
metadata + streamUrl
  ↓
playback

For search:

/search?q=...
  ↓
track result
  ↓
/track?id=...
  ↓
playback

For autoplay:

current track
  ↓
/recommendations?id=...
  ↓
candidate queue
  ↓
/track or /stream

For lyrics:

track ID
  ↓
/lyrics?id=...
  ↓
synchronized lyrics
39. Security

Never publish:

DEEZER_ARL
DEEZER_ARL_2
DEEZER_ARL_3
...

Do not put ARLs in:

Git commits
GitHub Issues
Screenshots
Discord messages
Public logs
Error reports

If an ARL is accidentally exposed, replace it immediately.

40. Troubleshooting
/ping says an ARL is expired

Replace the corresponding variable:

DEEZER_ARL

or:

DEEZER_ARL_2

Then redeploy.

/ping says active but lossless is false

The account authenticated successfully, but the FLAC playback test did not succeed.

Check:

lossless_check

and any returned error information.

Search works but playback fails

Check:

/ping
can_lossless
Requested quality
Cloudflare Worker logs
GitHub Issues
KV does not appear to work

Make sure the binding name is exactly:

GENERAL_MUSIC_CACHE

The Worker can still function without KV, so a missing binding may not immediately produce an obvious error.

Everything suddenly stops working

Deezer's internal playback interfaces can change.

Check:

/ping
Cloudflare Worker logs
Recent repository commits
GitHub Issues
41. Disclaimer

This project is not an official Deezer API implementation.

It uses Deezer catalog functionality and internal/private playback mechanisms. These interfaces can change without notice.

This documentation and the Worker were AI-generated with human-directed development and testing. They are not guaranteed to remain correct forever.

If you encounter a bug, broken endpoint, changed response, authentication problem, Cloudflare issue, or playback failure, please use the repository's GitHub Issues page when viewing the repo.

When opening an issue, include:

Endpoint
Query parameters, with secrets removed
HTTP status
Sanitized response
Cloudflare Worker logs
Expected behavior
Actual behavior

Never include your ARL or other private credentials in an issue.
