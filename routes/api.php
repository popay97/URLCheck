<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\CheckUrlController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/
//GOOGLE API KEY FOR SAFE BROWSING: AIzaSyCiPZTdMqIPbFWEfEDnfMfg-w1qIDq4JFo

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    if (
        $request->header('x-api-key')
        && $request->header('x-api-key') === 'YWxsZXNvbmxpbmUubmw='
    ) {
        return $request->user();
    }
    return response()->json(['message' => 'Unauthorized'], 401);
});

//define post route for /api/v1/checkurl that takes a url from the request body and returns a canonicalized url using checkrl function from CheckUrlController
Route::post('/v1/checkurl', [CheckUrlController::class, 'checkUrl']);
