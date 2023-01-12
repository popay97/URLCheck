<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use App\Models\Lists;
use App\Models\Threats;
use Illuminate\Routing\Controller as BaseController;
//import Request class
use Illuminate\Http\Request;

class CheckUrlController extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;
    function getPrefixSuffixExpressions($url)
    {
        $expressions = array();

        // Parse the URL into its components
        $parsed_url = parse_url($url);

        // Get the host and path components
        $host = $parsed_url['host'];
        $path = $parsed_url['path'];
        $query = isset($parsed_url['query']) ? $parsed_url['query'] : '';

        // Split the host into its individual components
        $host_parts = explode('.', $host);

        // Try the exact hostname
        $expressions[] = $host . $path . ($query ? '?' . $query : '');

        // Try up to four hostnames formed by starting with the last five components and successively removing the leading component
        for ($i = count($host_parts) - 1; $i >= max(0, count($host_parts) - 5); $i--) {
            $sub_host = implode('.', array_slice($host_parts, $i));
            $expressions[] = $sub_host . $path . ($query ? '?' . $query : '');
        }

        // Try the exact path with query parameters
        $expressions[] = $host . $path . ($query ? '?' . $query : '');

        // Try the exact path without query parameters
        $expressions[] = $host . $path;

        // Try four paths formed by starting at the root and successively appending path components, including a trailing slash
        $path_parts = explode('/', $path);
        $curr_path = '/';
        for ($i = 1; $i < count($path_parts); $i++) {
            $curr_path .= $path_parts[$i] . '/';
            $expressions[] = $host . $curr_path;
        }

        return $expressions;
    }
    function getHashes($expressions)
    {
        $hashes = array();
        foreach ($expressions as $expression) {
            $hashes[] = hash('sha256', $expression);
        }
        return $hashes;
    }
    function getHashPrefixes($hashes, $prefix_length)
    {
        $prefixes = array();
        foreach ($hashes as $hash) {
            $prefixes[] = substr($hash, 0, $prefix_length);
        }
        return $prefixes;
    }
    function Canonicalize($url)
    {
        //First, remove tab (0x09), CR (0x0d), and LF (0x0a) characters from the URL. Do not remove escape sequences for these characters (e.g. '%0a').
        $url = str_replace(array("\t", "\r", "  "), "", $url);
        $url = str_replace(array("\n"), "", $url);

        //Second, if the URL ends in a fragment, remove the fragment. For example, shorten "http://google.com/#frag" to "http://google.com/".
        if (strpos($url, '#') !== false) {
            $url = substr($url, 0, strpos($url, '#'));
        }
        //Third, repeatedly percent-unescape the URL until it has no more percent-escapes.
        while (strpos($url, '%') !== false) {
            $url = urldecode($url);
        }
        //extract the hostname from the url
        $hostname = parse_url($url, PHP_URL_HOST);
        //Remove all leading and trailing dots.
        $hostname = trim($hostname, '.');
        //Replace consecutive dots with a single dot.
        $hostname = preg_replace('/\.{2,}/', '.', $hostname);
        //check if the hostname is an IP address, normalize it to 4 dot-separated decimal values. check all possible encodings of IPv4 addresses.
        if (filter_var($hostname, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $hostname = long2ip(ip2long($hostname));
        }

        //Fourth, lowercase the hostname.
        $hostname = strtolower($hostname);

        //extract the path from the url
        $path = parse_url($url, PHP_URL_PATH);
        //Resolve the sequences "/../" and "/./" in the path by replacing "/./" with "/", and removing "/../" along with the preceding path component.
        //Do not apply these path canonicalizations to the query parameters.
        //extract query parameters first
        $query = parse_url($url, PHP_URL_QUERY);
        //remove query parameters from the path
        $path = str_replace('?' . $query, '', $path);
        $path = preg_replace('/\/\.\//', '/', $path);
        $path = preg_replace('/\/\.\.\//', '/', $path);
        //Replace runs of consecutive slashes with a single slash character.
        $path = preg_replace('/\/{2,}/', '/', $path);
        //reconstruct the url with the canonicalized hostname and path, carefull to preserve the query parameters and https o http
        $url = parse_url($url, PHP_URL_SCHEME) . '://' . $hostname . $path . '?' . $query;
        if (substr($url, -1) == '?') {
            $url = substr($url, 0, -1);
        }

        return $url;
    }
    function computePrefixSufix($url)
    {
        $expressions = array();

        // Parse the URL into its components
        $parsed_url = parse_url($url);

        // Get the host and path components
        $host = $parsed_url['host'];
        $path = $parsed_url['path'];
        $query = isset($parsed_url['query']) ? $parsed_url['query'] : '';

        // Split the host into its individual components
        $host_parts = explode('.', $host);

        // Try the exact hostname
        $expressions[] = $host . $path . ($query ? '?' . $query : '');

        // Try up to four hostnames formed by starting with the last five components and successively removing the leading component
        for ($i = count($host_parts) - 1; $i >= max(0, count($host_parts) - 5); $i--) {
            $sub_host = implode('.', array_slice($host_parts, $i));
            $expressions[] = $sub_host . $path . ($query ? '?' . $query : '');
        }

        // Try the exact path with query parameters
        $expressions[] = $host . $path . ($query ? '?' . $query : '');

        // Try the exact path without query parameters
        $expressions[] = $host . $path;

        // Try four paths formed by starting at the root and successively appending path components, including a trailing slash
        $path_parts = explode('/', $path);
        $curr_path = '/';
        for ($i = 1; $i < count($path_parts); $i++) {
            $curr_path .= $path_parts[$i] . '/';
            $expressions[] = $host . $curr_path;
        }

        return $expressions;
    }
    public function checkUrl(Request $request)
    {
        $url = $request->input('url');
        if (Config::get('global.dbUpdateInProgress') == 1) {
            //database update in progress, use lookup api to check if url is safe
            $threatTypes = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION', 'THREAT_TYPE_UNSPECIFIED'];
            $platformTypes = ['WINDOWS', 'LINUX', 'ANDROID', 'OSX', 'IOS', 'CHROME'];
            $response = Http::withHeaders([
                'Content-Type' => 'application/json',
            ])->post('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . Config::get('global.google_api_key'), [
                'client' => [
                    'clientId' => 'urlcheck',
                    'clientVersion' => '1.0.0',
                ],
                'threatInfo' => [
                    'threatTypes' => $threatTypes,
                    'platformTypes' => $platformTypes,
                    'threatEntryTypes' => ['URL'],
                    'threatEntries' => [
                        ['url' => $url],
                    ]
                ],
            ]);

            if ($response->successful()) {
                $lists = [];
                $data = json_decode($response->body(), true);
                //if data contains no keys, url is safe
                if (empty($data)) {
                    return response()->json(['status' => 'safe']);
                } else {
                    foreach ($data['matches'] as $match) {
                        $lists[] = ['platform_type' => $match['platformType'], 'threat_type' => $match['threatType'], 'threat_entry_type' => $match['threatEntryType']];
                    }
                    return response()->json(['status' => 'unsafe', 'lists' => $lists]);
                }
            } else {
                return response()->json(['status' => 'server_unreachable']);
            }
        }
        $url = $this->Canonicalize($url);
        $expressions = $this->getPrefixSuffixExpressions($url);
        $hashes = $this->getHashes($expressions);
        $prefixes = $this->getHashPrefixes($hashes, 4);
        $prefixes = array_unique($prefixes);
        $threats = Threats::whereIn('hash', $prefixes)->get();
        $lists = [];

        foreach ($threats as $threat) {
            $lists[] = Lists::where('id', $threat->list_id)->first();
        }
        array_unique($lists);
        if (empty($lists)) {
            return response()->json(['status' => 'safe']);
        } else {
            //check against fullHashes.find google api to see if url is safe
            $threatTypes = [];
            $platformTypes = [];
            $threatEnytyTypes = [];
            $clientStates = [];
            foreach ($lists as $list) {
                $threatTypes[] = $list->threat_type;
                $platformTypes[] = $list->platform_type;
                $threatEnytyTypes[] = $list->threat_entry_type;
                $clientStates[] = $list->state;
            }
            $threatTypes = array_unique($threatTypes);
            $platformTypes = array_unique($platformTypes);
            $threatEnytyTypes = array_unique($threatEnytyTypes);
            $threatEntries = [];
            foreach ($threats as $threat) {
                $threatEntries[] = ['hash' => $threat->hash];
            }

            $response = Http::withHeaders([
                'Content-Type' => 'application/json',
            ])->post('https://safebrowsing.googleapis.com/v4/fullHashes:find?key=' . Config::get('global.google_api_key'), [
                'client' => [
                    'clientId' => 'urlcheck',
                    'clientVersion' => '1.0.0',
                ],
                'clientStates' => $clientStates,
                'threatInfo' => [
                    'threatTypes' => $threatTypes,
                    'platformTypes' => $platformTypes,
                    'threatEntryTypes' => $threatEnytyTypes,
                    'threatEntries' => $threatEntries,
                ],
            ]);

            if ($response->successful()) {
                $data = json_decode($response->body(), true);
                //if data contains no keys, url is safe
                if (empty($data)) {
                    return response()->json(['status' => 'safe']);
                } else {
                    $listsToReturn = [];
                    foreach ($data['matches'] as $match) {
                        $listsToReturn[] = ['platform_type' => $match['platformType'], 'threat_type' => $match['threatType'], 'threat_entry_type' => $match['threatEntryType']];
                    }
                    return response()->json(['status' => 'unsafe', 'lists' => $listsToReturn]);
                }
            } else {
                return response()->json(['status' => 'server_unreachable']);
            }
        }
    }
}
