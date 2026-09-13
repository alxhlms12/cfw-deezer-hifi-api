# cfw-deezer-hifi-api

A Cloudflare Worker API for Deezer catalog access, lossless HiFi playback resolution, lyrics, recommendations, streaming, and multi-ARL routing.

## Documentation

The complete setup guide, configuration reference, environment variables, routing information, API endpoints, deployment instructions, troubleshooting, and usage documentation are available from the Worker itself:

**https://your-worker.workers.dev/docs**

Replace `your-worker` with the hostname of your deployed Cloudflare Worker.

## Quick Start

1. Upload `worker.js` to a Cloudflare Worker.
2. Configure the required environment variables and secrets.
3. Configure one or more Deezer ARLs.
4. Deploy the Worker.
5. Open `/docs` on your deployed Worker for the complete configuration and API reference.

Example:

```text
https://your-worker.workers.dev/docs
```

## Features

* Deezer catalog search and metadata
* Track, album, artist, playlist, chart, genre, and radio endpoints
* Lossless FLAC playback
* 16-bit / 44.1 kHz HiFi metadata
* 1411 kbps uncompressed lossless bitrate reporting
* FLAC and MP3 playback support
* Worker-side stream proxying and decryption
* Lyrics
* Personalized recommendations
* Multi-ARL routing
* Configurable load balancing
* Caching
* Rate limiting
* API-key authentication
* Public and private API modes
* Runtime diagnostics
* `/routing`
* `/env`
* `/docs`

## Configuration

Do not put private ARLs, API keys, or other secrets directly into `worker.js`.

Use Cloudflare Worker environment variables and secrets as described in:

**https://your-worker.workers.dev/docs**

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE).
