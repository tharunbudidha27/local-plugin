<?php
// This file is part of Moodle - https://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

/**
 * Data transfer object: playback payload.
 *
 * @package    local_fastpix
 * @copyright  2026 FastPix Inc. <support@fastpix.io>
 * @license    https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace local_fastpix\dto;

/**
 * Public playback DTO returned from \local_fastpix\service\playback_service::resolve.
 * Field names match ADR-013's documented consumer-contract surface exactly
 * (CC8). The four sibling plugins (mod_fastpix, filter_fastpix,
 * tinymce_fastpix, future viewer) consume this DTO directly — renaming a
 * field here is a major version bump and an ADR.
 *
 * @package    local_fastpix
 * @copyright  2026 FastPix Inc. <support@fastpix.io>
 * @license    https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class playback_payload {
    /**
     * Constructor.
     **/    public function __construct(
    /** @var string Playbackid. */
    public readonly string $playbackid,
    /** @var string Playbacktoken. */
    public readonly string $playbacktoken,
    /** @var int Expiresatts. */
    public readonly int $expiresatts,
    /** @var bool Drmrequired. */
    public readonly bool $drmrequired,
    /** @var ?string Accentcolor. */
    public readonly ?string $accentcolor,
    /** @var bool Defaultshowcaptions. */
    public readonly bool $defaultshowcaptions,
) {
}

    /**
     * Construct from an asset row + freshly-minted JWT + activity-level
     * overrides. Activity-level fields (accent_color, default_show_captions)
     * come from the caller, NOT the asset — they're owned by the consuming
     * plugin's activity row, not by local_fastpix.
     *
     * @param \stdClass $asset       Row from local_fastpix_asset.
     * @param string    $jwt         Signed JWT from jwt_signing_service.
     * @param int       $ttlseconds JWT TTL in seconds.
     * @param ?string   $accentcolor Optional brand colour (CSS string) from the caller.
     * @param bool      $defaultshowcaptions Whether captions are on by default for this activity.
     * @param \stdClass $asset
     * @param string $jwt
     * @param int $ttlseconds
     * @param ?string $accentcolor
     * @param bool $defaultshowcaptions
     * @return self
     */
public static function from_asset_and_jwt(
    \stdClass $asset,
    string $jwt,
    int $ttlseconds,
    ?string $accentcolor = null,
    bool $defaultshowcaptions = false,
): self {
    return new self(
        playback_id:           (string)$asset->playback_id,
        playback_token:        $jwt,
        expires_at_ts:         time() + $ttlseconds,
        drm_required:          (bool)($asset->drm_required ?? false),
        accent_color:          $accentcolor,
        default_show_captions: $defaultshowcaptions,
    );
}
}
