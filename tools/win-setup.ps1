#
# win-setup - Prepare a Windows development environment for building Wireshark.
#
# Copyright 2015 Gerald Combs <gerald@wireshark.org>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

#requires -version 2

# To do:
# - Use Expand-Archive instead of `cmake -E tar`? That requires PS >= 5.0

<#
.SYNOPSIS
Prepare a Windows development environment for building Wireshark.

.DESCRIPTION
This script downloads and extracts third-party libraries required to compile
Wireshark.

.PARAMETER Destination
Specifies the destination directory for the text files. The path must
contain the pattern "wireshark-*-libs".

.PARAMETER Platform
Target platform. Must be one of "win64" or "arm64".

.PARAMETER CMakeExecutable
Specifies the path to the CMake executable, which is used to extract archives.

.INPUTS
-Destination Destination directory.
-Platform Target platform.
-CMakeExecutable Path to CMake.

.OUTPUTS
A set of libraries required to compile Wireshark on Windows, along with
their compressed archives.
A manifest file (library-manifest.xml)

.EXAMPLE
C:\PS> .\tools\win-setup.ps1 -Destination C:\wireshark-master-64-libs -Platform win64
#>

Param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateScript({$_ -like "*[/\]wireshark-*-libs"})]
    [String]
    $Destination,

    [Parameter(Mandatory=$true, Position=1)]
    [ValidateSet("win64", "arm64")]
    [String]
    $Platform,

    [Parameter(Mandatory=$false, Position=3)]
    [ValidateScript({$_ | Test-Path -Type leaf })]
    [String]
    $CMakeExecutable = "CMake"
)

# Variables

# We create and delete files and directories. Bail out at the first sign of
# trouble instead of trying to catch exceptions everywhere.
$ErrorActionPreference = "Stop"

# Archive file / SHA256
$X64Archives = @{
    "AirPcap/AirPcap_Devpack_4_1_0_1622.zip" = "09d637f28a79b1d2ecb09f35436271a90c0f69bd0a1ee82b803abaaf63c18a69";
    "bcg729/bcg729-1.0.4-win64ws.zip" = "9a095fda4c39860d96f0c568830faa6651cd17635f68e27aa6de46c689aa0ee2";
    "brotli/brotli-1.0.9-1-win64ws.zip" = "3f8d24aec8668201994327ff8d8542fe507d1d468a500a1aec50d0415f695aab";
    "c-ares/c-ares-1.18.1-1-win64ws.zip" = "61183970996150e2eb137dfa7f5842ffa6e0eec2819634d5bdadc84013f8411d";
    "gnutls/gnutls-3.7.9-1-x64-mingw-dynamic-ws.zip" = "d60148df60ac8dfde59bc89d4141fe3ee5735a0bd53f7d28dbb3f6f69149c23a";
    "krb5/krb5-1.20.1-1-x64-windows-ws.zip" = "a1e5c582afce6e2f72f0f5bd66df2c0f3cc984532a1da5314fc89d7b7f29cdbf";
    "libgcrypt/libgcrypt-1.10.2-2-x64-mingw-dynamic-ws.zip" = "477cfce91d791b34df75a5ad83626f1ac2ee147eff7965e52266a4fc3da0f920";
    "libilbc/libilbc-2.0.2-4-x64-windows-ws.zip" = "4f35a1ffa03c89bf473f38249282a7867b203988d2b6d3d2f0924764619fd5f5";
    "libmaxminddb/libmaxminddb-1.4.3-1-win64ws.zip" = "ee89944a19ab6e1c873bdecb9fc6205d317c41e6da6ec1d30bc892fddfd143da";
    "libpcap/libpcap-1.10.1-1-win64ws.zip" = "59f8e0e90a3ab5671df561266ed2b02870a6f8f3a895b80c9db19fea9a12ffb2";
    "libsmi/libsmi-2021-01-15-1-x64-windows-ws.zip" = "54a40c061132edaf1725a6141f88e02f607a90c3d577eacae7f8c16c7757a84c";
    "libssh/libssh-0.10.5-1-x64-mingw-dynamic-ws.zip" = "9c1410d1033a540d118e17938905144956291b4c6ca7a9b7af6959b2632a1aaa";
    "lua/lua-5.2.4-unicode-win64-vc14.zip" = "e8968d2c7871ce1ea82cbd29ac1b3a2c59d3dec25e483c5e12de85df66f5d928";
    "lz4/lz4-1.9.3-1-win64ws.zip" = "7129515893ffdc439f4ffe9673c4bc43f9042e910bb2607e68dde6b99a1ab058";
    "minizip/minizip-1.2.11-4-win64ws.zip" = "dd6bf24e2d946465ad19aa4f8c38e0db91da6585887935de68011982cd6fb2cb";
    "nghttp2/nghttp2-1.49.0-1-win64ws.zip" = "215919ec20be62101d4704ec2464bfb72c5677126c5245b92ba495a3d30642ca";
    "opus/opus-1.3.1-3-win64ws.zip" = "1f7a55a6d2d7215dffa4a43bca8ca05024bd4ba1ac3d0d0c405fd38b09cc2205";
    "pcre2/pcre2-10.40-1-win64ws.zip" = "17eee615990b23bc859a862c19f5ac10c61776587603bc452285abe073a0fad9";
    "sbc/sbc-2.0-1-x64-windows-ws.zip" = "d1a58f977dcffa168b11b280bd10228191582d263b7c901e50cde7c1c43d9c04";
    "snappy/snappy-1.1.9-1-win64ws.zip" = "fa907724be019bcc55d27ebe88257ba8898b5c38b719099b8164ac78600d81cc";
    "spandsp/spandsp-0.0.6-5-x64-windows-ws.zip" = "cbb18310876ec6f081662253a2d37f5174ac60c58b0b7cd6759852fbcfaa7d7f";
    "speexdsp/speexdsp-1.21.1-1-win64ws.zip" = "d36db62e64ffaee38d9f607bef07d3778d8957ad29757f3eba169eb135f1a4e5";
    "vcpkg-export/vcpkg-export-20220726-1-win64ws.zip" = "b1eaa8124802532fa8d30789219906f90fb80908844e4458327b3f73995a44b0";
    "WinSparkle/WinSparkle-0.8.0-4-gb320893.zip" = "3ae42326bcd34594bc21b1e7948863a839ee76e87d9f4cf6b59b9d9f9a083881";
    "zstd/zstd-1.5.2-1-win64ws.zip" = "d920afe636951cfcf144824d9c075d1f2c13387f4739152fe185fd9c09fc58f2";
}

$Arm64Archives = @{
    "bcg729/bcg729-1.1.1-1-win64armws.zip" = "f4d76b9acf0d0e12e87a020e9805d136a0e8775e061eeec23910a10828153625";
    "brotli/brotli-1.0.9-1-win64armws.zip" = "5ba1b62ebc514d55c3eae85a00ff107e587b6e7cb1275e2d33fcddcd49f8e2af";
    "c-ares/c-ares-1.19.0-1-win64armws.zip" = "3e02db0c77303fcd5e9b85f2abe7b48ed79b0ed5d3bdada291a71842e91a6215";
    "gnutls/gnutls-3.7.9-1-arm64-mingw-dynamic-ws.zip" = "932f07fbb33bf1125dbd7be2806cd0e84fd3fc957f3dbc1245b47699d10982c7";
    "krb5/krb5-1.20.1-1-arm64-windows-ws.zip" = "6afe3185ea7621224544683a89d7c724d32bef6f1b552738dbc713ceb2151437";
    "libgcrypt/libgcrypt-1.10.2-2-arm64-mingw-dynamic-ws.zip" = "cd42fa2739a204e129d655e1b0dda83ceb27399812b8b2eccddae4a9ecd8d0ce";
    "libilbc/libilbc-2.0.2-4-arm64-windows-ws.zip" = "00a506cc1aac8a2e31856e463a555d899b5a6ccf376485a124104858ccf0be6d";
    "libmaxminddb/libmaxminddb-1.4.3-1-win64armws.zip" = "9996327f301cb4a4de797bc024ad0471acd95c1850a2afc849c57fcc93360610";
    "libpcap/libpcap-1.10.1-1-win64armws.zip" = "c0c5d42d96cc407303d71ba5afd06615c660228fa2260d7ecbc8453140529137";
    "libsmi/libsmi-2021-01-15-1-arm64-windows-ws.zip" = "938249047575aaab2a4f99945b44a46fe3e7190f7a75d6e985d8a6f49dec9ceb";
    "libssh/libssh-0.10.5-1-arm64-mingw-dynamic-ws.zip" = "b99c9573d9a30ba2898ce6ac131b23b1699009761d5dbe351a1a958cca0f85ca";
    "lua/lua-5.2.4-unicode-arm64-windows-vc17.zip" = "5848e23352e35b69f4cdabaca3754c2c5fb11e5461bb92b71e059e558e4b2d12";
    "lz4/lz4-1.9.4-1-win64armws.zip" = "59a3ed3f9161be7614a89afd2ca21c43f26dd916afd4aa7bfdc4b148fb10d485";
    "minizip/minizip-1.2.13-1-win64armws.zip" = "b1e79d8feb01b89cebc1e9fed7765d29f5eb412d11bfcf07217fb645863deb2c";
    "nghttp2/nghttp2-1.51.0-1-win64armws.zip" = "ede5c53fd46ab12b15ff9758cdc2891731bc1475c589681aa10e6aaf2217656c";
    "opus/opus-1.4-1-win64armws.zip" = "51d10381360d5691b2022dde5b284266d9b0ce9a3c9bd7e86f9a4ff1a4f7d904";
    "pcre2/pcre2-10.40-1-win64armws.zip" = "e8fc7542845900e7dbecfa4a10d7ec17edf72bc0e8d433268bee111f1d4947d3";
    "sbc/sbc-2.0-1-arm64-windows-ws.zip" = "83cfe4a8b6fa5bae253ecacc1c02e6e4c61b4ad9ad0e5e63f0f30422fb6eac96";
    "snappy/snappy-1.1.9-1-win64armws.zip" = "f3f6ec841024d18df06934ff70f44068a4e8f1008eca1f363257645647f74d4a";
    "spandsp/spandsp-0.0.6-5-arm64-windows-ws.zip" = "fdf01e3c33e739ff9399b7d42cd8230c97cb27ce51865a0f06285a8f68206b6c";
    "speexdsp/speexdsp-1.2.1-1-win64armws.zip" = "1759a9193065f27e50dd79dbb1786d24031ac43ccc48c40dca46d8a48552e3bb";
    "vcpkg-export/vcpkg-export-20230502-1-win64armws.zip" = "94bc2d98bcb86e79569c7bf638cde8d63175cd65cf07cc219890cdc713707ce9";
    "WinSparkle/WinSparkle-0.8.0-4-gb320893.zip" = "3ae42326bcd34594bc21b1e7948863a839ee76e87d9f4cf6b59b9d9f9a083881";
    "zstd/zstd-1.5.5-1-win64armws.zip" = "0e448875380cc5d5f5539d994062201bfa564e4a27466bc3fdfec84d9008e51d";
}

# Subdirectory to extract an archive to
$ArchivesSubDirectory = @{
    "AirPcap/AirPcap_Devpack_4_1_0_1622.zip" = "AirPcap_Devpack_4_1_0_1622";
}

# Plain file downloads

$X64Files = @{
    # Nothing here
}

$Arm64Files = @{
    # Nothing here
}

$Archives = $X64Archives;
$Files = $X64Files;

if ($Platform -eq "arm64") {
    $Archives = $Arm64Archives;
    $Files = $Arm64Files;
}

$CurrentManifest = $Archives + $Files

$CleanupItems = @(
    "bcg729-1.0.4-win??ws"
    "brotli-1.0.*-win??ws"
    "c-ares-1.9.1-1-win??ws"
    "c-ares-1.1*-win??ws"
    "gnutls-3.?.*-*-win??ws"
    "krb5-*-win??ws"
    "libgcrypt-*-win??ws"
    "libilbc-2.0.2-3-win??ws"
    "libmaxminddb-1.4.3-1-win??ws"
    "libpcap-1.9.1-1-win??ws"
    "libsmi-0.4.8"
    "libsmi-svn-40773-win??ws"
    "libssh-0.*-win??ws"
    "libxml2-*-win??ws"
    "lua5.1.4"
    "lua5.2.?"
    "lua5.2.?-win??"
    "lua-5.?.?-unicode-win??-vc??"
    "lz4-*-win??ws"
    "MaxMindDB-1.3.2-win??ws"
    "minizip-*-win??ws"
    "nghttp2-*-win??ws"
    "opus-1.3.1-?-win??ws"
    "pcre2-*-win??ws"
    "sbc-1.3-win??ws"
    "snappy-1.1.*-win??ws"
    "spandsp-0.0.6-win??ws"
    "speexdsp-*-win??ws"
    "user-guide"
    "vcpkg-export-*-win??ws"
    "zstd-*-win??ws"
    "AirPcap_Devpack_4_1_0_1622"
    "WinSparkle-0.3-44-g2c8d9d3-win??ws"
    "WinSparkle-0.5.?"
    "current-tag.txt"
    "library-manifest.xml"
)

# The dev-libs site repository is at
# https://gitlab.com/wireshark/wireshark-development-libraries
[Uri] $DownloadPrefix = "https://dev-libs.wireshark.org/windows/packages"
$proxy = $null

# Functions

# Verifies the contents of a file against a SHA256 hash.
# Returns success (0) if the file exists and verifies.
# Returns error (1) if the file does not exist.
# Returns error (2) if the integrity check fails (an error is also printed).
function VerifyIntegrity($filename, $hash) {
    # Use absolute path because PS and .NET may have different working directories.
    $filepath = Convert-Path -Path $filename -ErrorAction SilentlyContinue
    if (-not ($filepath)) {
        return 1
    }
    # may throw due to permission error, I/O error, etc.
    try { $stream = [IO.File]::OpenRead($filepath) } catch { throw }

    try {
        $sha256 = New-Object Security.Cryptography.SHA256Managed
        $binaryHash = $sha256.ComputeHash([IO.Stream]$stream)
        $hexHash = ([System.BitConverter]::ToString($binaryHash) -Replace "-").ToLower()
        $hash = $hash.ToLower()
        if ($hexHash -ne $hash) {
            Write-Warning "$($filename): computed file hash $hexHash did NOT match $hash"
            return 2
        }
        return 0
    } finally {
        $stream.Close()
    }
}

# Downloads a file and checks its integrity. If a corrupt file already exists,
# it is removed and re-downloaded. Succeeds only if the SHA256 hash matches.
function DownloadFile($fileName, $fileHash, [Uri] $fileUrl = $null) {
    if ([string]::IsNullOrEmpty($fileUrl)) {
        $fileUrl = "$DownloadPrefix/$fileName"
    }
    $destinationFile = "$Destination\" + [string](Split-Path -Leaf $fileName)
    if (Test-Path $destinationFile -PathType 'Leaf') {
        if ((VerifyIntegrity $destinationFile $fileHash) -ne 0) {
            Write-Output "$fileName is corrupt, removing and retrying download."
            Remove-Item $destinationFile
        } else {
            Write-Output "$fileName already there; not retrieving."
            return
        }
    }

    if (-not ($Script:proxy)) {
        $Script:proxy = [System.Net.WebRequest]::GetSystemWebProxy()
        $Script:proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    }

    Write-Output "Downloading $fileUrl into $Destination"
    $webClient = New-Object System.Net.WebClient
    $webClient.proxy = $Script:proxy
    $webClient.DownloadFile($fileUrl, "$destinationFile")
    Write-Output "Verifying $destinationFile"
    if ((VerifyIntegrity $destinationFile $fileHash) -ne 0) {
        Write-Output "Download is corrupted, aborting!"
        exit 1
    }
}

function DownloadArchive($fileName, $fileHash, $subDir) {
    DownloadFile $fileName $fileHash
    $archiveFile = "$Destination\" + [string](Split-Path -Leaf $fileName)
    $archiveDir = "$Destination\$subDir"
    if ($subDir -and -not (Test-Path $archiveDir -PathType 'Container')) {
        New-Item -ItemType Directory -Path $archiveDir > $null
    }

    $activity = "Extracting into $($archiveDir)"
    Write-Progress -Activity "$activity" -Status "Extracting $archiveFile using CMake ..."
    Push-Location "$archiveDir"
    & "$CMakeExecutable" -E tar xf "$archiveFile" 2>&1 | Set-Variable -Name CMakeOut
    $cmStatus = $LASTEXITCODE
    Pop-Location
    Write-Progress -Activity "$activity" -Status "Done" -Completed
    if ($cmStatus -gt 0) {
        Write-Output $CMakeOut
        exit 1
    }
}

# On with the show

# Make sure $Destination exists and do our work there.
if ( -not (Test-Path $Destination -PathType 'Container') ) {
    New-Item -ItemType 'Container' "$Destination" > $null
}

# CMake's file TO_NATIVE_PATH passive-aggressively omits the drive letter.
Set-Location "$Destination"
$Destination = $(Get-Item -Path ".\")
Write-Output "Working in $Destination"

# Check our last known state
$destinationManifest = @{ "INVALID" = "INVALID" }
$manifestFile = "library-manifest.xml"
if ((Test-Path $manifestFile -PathType 'Leaf') -and -not ($Force)) {
    $destinationManifest = Import-Clixml $manifestFile
}

function ManifestList($manifestHash) {
    $manifestHash.keys | Sort | ForEach-Object { "$_ : $($manifestHash[$_])" }
}

if (Compare-Object -ReferenceObject (ManifestList($destinationManifest)) -DifferenceObject (ManifestList($CurrentManifest))) {
    Write-Output "Current library manifest not found. Refreshing."
    $activity = "Removing directories"
    foreach ($oldItem in $CleanupItems) {
        if (Test-Path $oldItem) {
            Write-Progress -Activity "$activity" -Status "Removing $oldItem"
            Remove-Item -force -recurse $oldItem
        }
    }
    Write-Progress -Activity "$activity" -Status "Done" -Completed
} else {
    Write-Output "Current library manifest found. Skipping download."
    exit 0
}

# Download files
foreach ($item in $Files.GetEnumerator() | Sort-Object -property key) {
    DownloadFile $item.Name $item.Value
}

# Download and extract archives
foreach ($item in $Archives.GetEnumerator() | Sort-Object -property key) {
    $subDir = $ArchivesSubDirectory[$item.Name]
    DownloadArchive $item.Name $item.Value $subDir
}

# Save our last known state
$CurrentManifest | Export-Clixml -Path $manifestFile -Encoding utf8
