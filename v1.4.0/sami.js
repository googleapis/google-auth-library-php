
window.projectVersion = 'v1.4.0';

(function(root) {

    var bhIndex = null;
    var rootPath = '';
    var treeHtml = '        <ul>                <li data-name="namespace:Google" class="opened">                    <div style="padding-left:0px" class="hd">                        <span class="glyphicon glyphicon-play"></span><a href="Google.html">Google</a>                    </div>                    <div class="bd">                                <ul>                <li data-name="namespace:Google_Auth" class="opened">                    <div style="padding-left:18px" class="hd">                        <span class="glyphicon glyphicon-play"></span><a href="Google/Auth.html">Auth</a>                    </div>                    <div class="bd">                                <ul>                <li data-name="namespace:Google_Auth_Cache" >                    <div style="padding-left:36px" class="hd">                        <span class="glyphicon glyphicon-play"></span><a href="Google/Auth/Cache.html">Cache</a>                    </div>                    <div class="bd">                                <ul>                <li data-name="class:Google_Auth_Cache_InvalidArgumentException" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Cache/InvalidArgumentException.html">InvalidArgumentException</a>                    </div>                </li>                            <li data-name="class:Google_Auth_Cache_Item" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Cache/Item.html">Item</a>                    </div>                </li>                            <li data-name="class:Google_Auth_Cache_MemoryCacheItemPool" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Cache/MemoryCacheItemPool.html">MemoryCacheItemPool</a>                    </div>                </li>                            <li data-name="class:Google_Auth_Cache_SysVCacheItemPool" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Cache/SysVCacheItemPool.html">SysVCacheItemPool</a>                    </div>                </li>                </ul></div>                </li>                            <li data-name="namespace:Google_Auth_Credentials" >                    <div style="padding-left:36px" class="hd">                        <span class="glyphicon glyphicon-play"></span><a href="Google/Auth/Credentials.html">Credentials</a>                    </div>                    <div class="bd">                                <ul>                <li data-name="class:Google_Auth_Credentials_AppIdentityCredentials" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Credentials/AppIdentityCredentials.html">AppIdentityCredentials</a>                    </div>                </li>                            <li data-name="class:Google_Auth_Credentials_GCECredentials" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Credentials/GCECredentials.html">GCECredentials</a>                    </div>                </li>                            <li data-name="class:Google_Auth_Credentials_IAMCredentials" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Credentials/IAMCredentials.html">IAMCredentials</a>                    </div>                </li>                            <li data-name="class:Google_Auth_Credentials_InsecureCredentials" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Credentials/InsecureCredentials.html">InsecureCredentials</a>                    </div>                </li>                            <li data-name="class:Google_Auth_Credentials_ServiceAccountCredentials" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Credentials/ServiceAccountCredentials.html">ServiceAccountCredentials</a>                    </div>                </li>                            <li data-name="class:Google_Auth_Credentials_ServiceAccountJwtAccessCredentials" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Credentials/ServiceAccountJwtAccessCredentials.html">ServiceAccountJwtAccessCredentials</a>                    </div>                </li>                            <li data-name="class:Google_Auth_Credentials_UserRefreshCredentials" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Credentials/UserRefreshCredentials.html">UserRefreshCredentials</a>                    </div>                </li>                </ul></div>                </li>                            <li data-name="namespace:Google_Auth_HttpHandler" >                    <div style="padding-left:36px" class="hd">                        <span class="glyphicon glyphicon-play"></span><a href="Google/Auth/HttpHandler.html">HttpHandler</a>                    </div>                    <div class="bd">                                <ul>                <li data-name="class:Google_Auth_HttpHandler_Guzzle5HttpHandler" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/HttpHandler/Guzzle5HttpHandler.html">Guzzle5HttpHandler</a>                    </div>                </li>                            <li data-name="class:Google_Auth_HttpHandler_Guzzle6HttpHandler" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/HttpHandler/Guzzle6HttpHandler.html">Guzzle6HttpHandler</a>                    </div>                </li>                            <li data-name="class:Google_Auth_HttpHandler_HttpHandlerFactory" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/HttpHandler/HttpHandlerFactory.html">HttpHandlerFactory</a>                    </div>                </li>                </ul></div>                </li>                            <li data-name="namespace:Google_Auth_Middleware" >                    <div style="padding-left:36px" class="hd">                        <span class="glyphicon glyphicon-play"></span><a href="Google/Auth/Middleware.html">Middleware</a>                    </div>                    <div class="bd">                                <ul>                <li data-name="class:Google_Auth_Middleware_AuthTokenMiddleware" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Middleware/AuthTokenMiddleware.html">AuthTokenMiddleware</a>                    </div>                </li>                            <li data-name="class:Google_Auth_Middleware_ScopedAccessTokenMiddleware" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Middleware/ScopedAccessTokenMiddleware.html">ScopedAccessTokenMiddleware</a>                    </div>                </li>                            <li data-name="class:Google_Auth_Middleware_SimpleMiddleware" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Middleware/SimpleMiddleware.html">SimpleMiddleware</a>                    </div>                </li>                </ul></div>                </li>                            <li data-name="namespace:Google_Auth_Subscriber" >                    <div style="padding-left:36px" class="hd">                        <span class="glyphicon glyphicon-play"></span><a href="Google/Auth/Subscriber.html">Subscriber</a>                    </div>                    <div class="bd">                                <ul>                <li data-name="class:Google_Auth_Subscriber_AuthTokenSubscriber" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Subscriber/AuthTokenSubscriber.html">AuthTokenSubscriber</a>                    </div>                </li>                            <li data-name="class:Google_Auth_Subscriber_ScopedAccessTokenSubscriber" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Subscriber/ScopedAccessTokenSubscriber.html">ScopedAccessTokenSubscriber</a>                    </div>                </li>                            <li data-name="class:Google_Auth_Subscriber_SimpleSubscriber" >                    <div style="padding-left:62px" class="hd leaf">                        <a href="Google/Auth/Subscriber/SimpleSubscriber.html">SimpleSubscriber</a>                    </div>                </li>                </ul></div>                </li>                            <li data-name="class:Google_Auth_ApplicationDefaultCredentials" >                    <div style="padding-left:44px" class="hd leaf">                        <a href="Google/Auth/ApplicationDefaultCredentials.html">ApplicationDefaultCredentials</a>                    </div>                </li>                            <li data-name="class:Google_Auth_CacheTrait" >                    <div style="padding-left:44px" class="hd leaf">                        <a href="Google/Auth/CacheTrait.html">CacheTrait</a>                    </div>                </li>                            <li data-name="class:Google_Auth_CredentialsLoader" >                    <div style="padding-left:44px" class="hd leaf">                        <a href="Google/Auth/CredentialsLoader.html">CredentialsLoader</a>                    </div>                </li>                            <li data-name="class:Google_Auth_FetchAuthTokenCache" >                    <div style="padding-left:44px" class="hd leaf">                        <a href="Google/Auth/FetchAuthTokenCache.html">FetchAuthTokenCache</a>                    </div>                </li>                            <li data-name="class:Google_Auth_FetchAuthTokenInterface" >                    <div style="padding-left:44px" class="hd leaf">                        <a href="Google/Auth/FetchAuthTokenInterface.html">FetchAuthTokenInterface</a>                    </div>                </li>                            <li data-name="class:Google_Auth_OAuth2" >                    <div style="padding-left:44px" class="hd leaf">                        <a href="Google/Auth/OAuth2.html">OAuth2</a>                    </div>                </li>                </ul></div>                </li>                </ul></div>                </li>                </ul>';

    var searchTypeClasses = {
        'Namespace': 'label-default',
        'Class': 'label-info',
        'Interface': 'label-primary',
        'Trait': 'label-success',
        'Method': 'label-danger',
        '_': 'label-warning'
    };

    var searchIndex = [
                    
            {"type": "Namespace", "link": "Google.html", "name": "Google", "doc": "Namespace Google"},{"type": "Namespace", "link": "Google/Auth.html", "name": "Google\\Auth", "doc": "Namespace Google\\Auth"},{"type": "Namespace", "link": "Google/Auth/Cache.html", "name": "Google\\Auth\\Cache", "doc": "Namespace Google\\Auth\\Cache"},{"type": "Namespace", "link": "Google/Auth/Credentials.html", "name": "Google\\Auth\\Credentials", "doc": "Namespace Google\\Auth\\Credentials"},{"type": "Namespace", "link": "Google/Auth/HttpHandler.html", "name": "Google\\Auth\\HttpHandler", "doc": "Namespace Google\\Auth\\HttpHandler"},{"type": "Namespace", "link": "Google/Auth/Middleware.html", "name": "Google\\Auth\\Middleware", "doc": "Namespace Google\\Auth\\Middleware"},{"type": "Namespace", "link": "Google/Auth/Subscriber.html", "name": "Google\\Auth\\Subscriber", "doc": "Namespace Google\\Auth\\Subscriber"},
            {"type": "Interface", "fromName": "Google\\Auth", "fromLink": "Google/Auth.html", "link": "Google/Auth/FetchAuthTokenInterface.html", "name": "Google\\Auth\\FetchAuthTokenInterface", "doc": "&quot;An interface implemented by objects that can fetch auth tokens.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\FetchAuthTokenInterface", "fromLink": "Google/Auth/FetchAuthTokenInterface.html", "link": "Google/Auth/FetchAuthTokenInterface.html#method_fetchAuthToken", "name": "Google\\Auth\\FetchAuthTokenInterface::fetchAuthToken", "doc": "&quot;Fetches the auth tokens based on the current state.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\FetchAuthTokenInterface", "fromLink": "Google/Auth/FetchAuthTokenInterface.html", "link": "Google/Auth/FetchAuthTokenInterface.html#method_getCacheKey", "name": "Google\\Auth\\FetchAuthTokenInterface::getCacheKey", "doc": "&quot;Obtains a key that can used to cache the results of #fetchAuthToken.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\FetchAuthTokenInterface", "fromLink": "Google/Auth/FetchAuthTokenInterface.html", "link": "Google/Auth/FetchAuthTokenInterface.html#method_getLastReceivedToken", "name": "Google\\Auth\\FetchAuthTokenInterface::getLastReceivedToken", "doc": "&quot;Returns an associative array with the token and\nexpiration time.&quot;"},
            
            
            {"type": "Class", "fromName": "Google\\Auth", "fromLink": "Google/Auth.html", "link": "Google/Auth/ApplicationDefaultCredentials.html", "name": "Google\\Auth\\ApplicationDefaultCredentials", "doc": "&quot;ApplicationDefaultCredentials obtains the default credentials for\nauthorizing a request to a Google service.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\ApplicationDefaultCredentials", "fromLink": "Google/Auth/ApplicationDefaultCredentials.html", "link": "Google/Auth/ApplicationDefaultCredentials.html#method_getSubscriber", "name": "Google\\Auth\\ApplicationDefaultCredentials::getSubscriber", "doc": "&quot;Obtains an AuthTokenSubscriber that uses the default FetchAuthTokenInterface\nimplementation to use in this environment.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\ApplicationDefaultCredentials", "fromLink": "Google/Auth/ApplicationDefaultCredentials.html", "link": "Google/Auth/ApplicationDefaultCredentials.html#method_getMiddleware", "name": "Google\\Auth\\ApplicationDefaultCredentials::getMiddleware", "doc": "&quot;Obtains an AuthTokenMiddleware that uses the default FetchAuthTokenInterface\nimplementation to use in this environment.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\ApplicationDefaultCredentials", "fromLink": "Google/Auth/ApplicationDefaultCredentials.html", "link": "Google/Auth/ApplicationDefaultCredentials.html#method_getCredentials", "name": "Google\\Auth\\ApplicationDefaultCredentials::getCredentials", "doc": "&quot;Obtains the default FetchAuthTokenInterface implementation to use\nin this environment.&quot;"},
            
            {"type": "Trait", "fromName": "Google\\Auth", "fromLink": "Google/Auth.html", "link": "Google/Auth/CacheTrait.html", "name": "Google\\Auth\\CacheTrait", "doc": "&quot;&quot;"},
                    
            {"type": "Class", "fromName": "Google\\Auth\\Cache", "fromLink": "Google/Auth/Cache.html", "link": "Google/Auth/Cache/InvalidArgumentException.html", "name": "Google\\Auth\\Cache\\InvalidArgumentException", "doc": "&quot;&quot;"},
                    
            {"type": "Class", "fromName": "Google\\Auth\\Cache", "fromLink": "Google/Auth/Cache.html", "link": "Google/Auth/Cache/Item.html", "name": "Google\\Auth\\Cache\\Item", "doc": "&quot;A cache item.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Cache\\Item", "fromLink": "Google/Auth/Cache/Item.html", "link": "Google/Auth/Cache/Item.html#method___construct", "name": "Google\\Auth\\Cache\\Item::__construct", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\Item", "fromLink": "Google/Auth/Cache/Item.html", "link": "Google/Auth/Cache/Item.html#method_getKey", "name": "Google\\Auth\\Cache\\Item::getKey", "doc": "&quot;Returns the key for the current cache item.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\Item", "fromLink": "Google/Auth/Cache/Item.html", "link": "Google/Auth/Cache/Item.html#method_get", "name": "Google\\Auth\\Cache\\Item::get", "doc": "&quot;Retrieves the value of the item from the cache associated with this object&#039;s key.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\Item", "fromLink": "Google/Auth/Cache/Item.html", "link": "Google/Auth/Cache/Item.html#method_isHit", "name": "Google\\Auth\\Cache\\Item::isHit", "doc": "&quot;Confirms if the cache item lookup resulted in a cache hit.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\Item", "fromLink": "Google/Auth/Cache/Item.html", "link": "Google/Auth/Cache/Item.html#method_set", "name": "Google\\Auth\\Cache\\Item::set", "doc": "&quot;Sets the value represented by this cache item.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\Item", "fromLink": "Google/Auth/Cache/Item.html", "link": "Google/Auth/Cache/Item.html#method_expiresAt", "name": "Google\\Auth\\Cache\\Item::expiresAt", "doc": "&quot;Sets the expiration time for this cache item.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\Item", "fromLink": "Google/Auth/Cache/Item.html", "link": "Google/Auth/Cache/Item.html#method_expiresAfter", "name": "Google\\Auth\\Cache\\Item::expiresAfter", "doc": "&quot;Sets the expiration time for this cache item.&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\Cache", "fromLink": "Google/Auth/Cache.html", "link": "Google/Auth/Cache/MemoryCacheItemPool.html", "name": "Google\\Auth\\Cache\\MemoryCacheItemPool", "doc": "&quot;Simple in-memory cache implementation.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Cache\\MemoryCacheItemPool", "fromLink": "Google/Auth/Cache/MemoryCacheItemPool.html", "link": "Google/Auth/Cache/MemoryCacheItemPool.html#method_getItem", "name": "Google\\Auth\\Cache\\MemoryCacheItemPool::getItem", "doc": "&quot;Returns a Cache Item representing the specified key.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\MemoryCacheItemPool", "fromLink": "Google/Auth/Cache/MemoryCacheItemPool.html", "link": "Google/Auth/Cache/MemoryCacheItemPool.html#method_getItems", "name": "Google\\Auth\\Cache\\MemoryCacheItemPool::getItems", "doc": "&quot;Returns a traversable set of cache items.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\MemoryCacheItemPool", "fromLink": "Google/Auth/Cache/MemoryCacheItemPool.html", "link": "Google/Auth/Cache/MemoryCacheItemPool.html#method_hasItem", "name": "Google\\Auth\\Cache\\MemoryCacheItemPool::hasItem", "doc": "&quot;Confirms if the cache contains specified cache item.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\MemoryCacheItemPool", "fromLink": "Google/Auth/Cache/MemoryCacheItemPool.html", "link": "Google/Auth/Cache/MemoryCacheItemPool.html#method_clear", "name": "Google\\Auth\\Cache\\MemoryCacheItemPool::clear", "doc": "&quot;Deletes all items in the pool.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\MemoryCacheItemPool", "fromLink": "Google/Auth/Cache/MemoryCacheItemPool.html", "link": "Google/Auth/Cache/MemoryCacheItemPool.html#method_deleteItem", "name": "Google\\Auth\\Cache\\MemoryCacheItemPool::deleteItem", "doc": "&quot;Removes the item from the pool.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\MemoryCacheItemPool", "fromLink": "Google/Auth/Cache/MemoryCacheItemPool.html", "link": "Google/Auth/Cache/MemoryCacheItemPool.html#method_deleteItems", "name": "Google\\Auth\\Cache\\MemoryCacheItemPool::deleteItems", "doc": "&quot;Removes multiple items from the pool.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\MemoryCacheItemPool", "fromLink": "Google/Auth/Cache/MemoryCacheItemPool.html", "link": "Google/Auth/Cache/MemoryCacheItemPool.html#method_save", "name": "Google\\Auth\\Cache\\MemoryCacheItemPool::save", "doc": "&quot;Persists a cache item immediately.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\MemoryCacheItemPool", "fromLink": "Google/Auth/Cache/MemoryCacheItemPool.html", "link": "Google/Auth/Cache/MemoryCacheItemPool.html#method_saveDeferred", "name": "Google\\Auth\\Cache\\MemoryCacheItemPool::saveDeferred", "doc": "&quot;Sets a cache item to be persisted later.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\MemoryCacheItemPool", "fromLink": "Google/Auth/Cache/MemoryCacheItemPool.html", "link": "Google/Auth/Cache/MemoryCacheItemPool.html#method_commit", "name": "Google\\Auth\\Cache\\MemoryCacheItemPool::commit", "doc": "&quot;Persists any deferred cache items.&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\Cache", "fromLink": "Google/Auth/Cache.html", "link": "Google/Auth/Cache/SysVCacheItemPool.html", "name": "Google\\Auth\\Cache\\SysVCacheItemPool", "doc": "&quot;SystemV shared memory based CacheItemPool implementation.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Cache\\SysVCacheItemPool", "fromLink": "Google/Auth/Cache/SysVCacheItemPool.html", "link": "Google/Auth/Cache/SysVCacheItemPool.html#method___construct", "name": "Google\\Auth\\Cache\\SysVCacheItemPool::__construct", "doc": "&quot;Create a SystemV shared memory based CacheItemPool.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\SysVCacheItemPool", "fromLink": "Google/Auth/Cache/SysVCacheItemPool.html", "link": "Google/Auth/Cache/SysVCacheItemPool.html#method_getItem", "name": "Google\\Auth\\Cache\\SysVCacheItemPool::getItem", "doc": "&quot;Returns a Cache Item representing the specified key.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\SysVCacheItemPool", "fromLink": "Google/Auth/Cache/SysVCacheItemPool.html", "link": "Google/Auth/Cache/SysVCacheItemPool.html#method_getItems", "name": "Google\\Auth\\Cache\\SysVCacheItemPool::getItems", "doc": "&quot;Returns a traversable set of cache items.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\SysVCacheItemPool", "fromLink": "Google/Auth/Cache/SysVCacheItemPool.html", "link": "Google/Auth/Cache/SysVCacheItemPool.html#method_hasItem", "name": "Google\\Auth\\Cache\\SysVCacheItemPool::hasItem", "doc": "&quot;Confirms if the cache contains specified cache item.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\SysVCacheItemPool", "fromLink": "Google/Auth/Cache/SysVCacheItemPool.html", "link": "Google/Auth/Cache/SysVCacheItemPool.html#method_clear", "name": "Google\\Auth\\Cache\\SysVCacheItemPool::clear", "doc": "&quot;Deletes all items in the pool.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\SysVCacheItemPool", "fromLink": "Google/Auth/Cache/SysVCacheItemPool.html", "link": "Google/Auth/Cache/SysVCacheItemPool.html#method_deleteItem", "name": "Google\\Auth\\Cache\\SysVCacheItemPool::deleteItem", "doc": "&quot;Removes the item from the pool.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\SysVCacheItemPool", "fromLink": "Google/Auth/Cache/SysVCacheItemPool.html", "link": "Google/Auth/Cache/SysVCacheItemPool.html#method_deleteItems", "name": "Google\\Auth\\Cache\\SysVCacheItemPool::deleteItems", "doc": "&quot;Removes multiple items from the pool.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\SysVCacheItemPool", "fromLink": "Google/Auth/Cache/SysVCacheItemPool.html", "link": "Google/Auth/Cache/SysVCacheItemPool.html#method_save", "name": "Google\\Auth\\Cache\\SysVCacheItemPool::save", "doc": "&quot;Persists a cache item immediately.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\SysVCacheItemPool", "fromLink": "Google/Auth/Cache/SysVCacheItemPool.html", "link": "Google/Auth/Cache/SysVCacheItemPool.html#method_saveDeferred", "name": "Google\\Auth\\Cache\\SysVCacheItemPool::saveDeferred", "doc": "&quot;Sets a cache item to be persisted later.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Cache\\SysVCacheItemPool", "fromLink": "Google/Auth/Cache/SysVCacheItemPool.html", "link": "Google/Auth/Cache/SysVCacheItemPool.html#method_commit", "name": "Google\\Auth\\Cache\\SysVCacheItemPool::commit", "doc": "&quot;Persists any deferred cache items.&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth", "fromLink": "Google/Auth.html", "link": "Google/Auth/CredentialsLoader.html", "name": "Google\\Auth\\CredentialsLoader", "doc": "&quot;CredentialsLoader contains the behaviour used to locate and find default\ncredentials files on the file system.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\CredentialsLoader", "fromLink": "Google/Auth/CredentialsLoader.html", "link": "Google/Auth/CredentialsLoader.html#method_fromEnv", "name": "Google\\Auth\\CredentialsLoader::fromEnv", "doc": "&quot;Load a JSON key from the path specified in the environment.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\CredentialsLoader", "fromLink": "Google/Auth/CredentialsLoader.html", "link": "Google/Auth/CredentialsLoader.html#method_fromWellKnownFile", "name": "Google\\Auth\\CredentialsLoader::fromWellKnownFile", "doc": "&quot;Load a JSON key from a well known path.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\CredentialsLoader", "fromLink": "Google/Auth/CredentialsLoader.html", "link": "Google/Auth/CredentialsLoader.html#method_makeCredentials", "name": "Google\\Auth\\CredentialsLoader::makeCredentials", "doc": "&quot;Create a new Credentials instance.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\CredentialsLoader", "fromLink": "Google/Auth/CredentialsLoader.html", "link": "Google/Auth/CredentialsLoader.html#method_makeHttpClient", "name": "Google\\Auth\\CredentialsLoader::makeHttpClient", "doc": "&quot;Create an authorized HTTP Client from an instance of FetchAuthTokenInterface.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\CredentialsLoader", "fromLink": "Google/Auth/CredentialsLoader.html", "link": "Google/Auth/CredentialsLoader.html#method_makeInsecureCredentials", "name": "Google\\Auth\\CredentialsLoader::makeInsecureCredentials", "doc": "&quot;Create a new instance of InsecureCredentials.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\CredentialsLoader", "fromLink": "Google/Auth/CredentialsLoader.html", "link": "Google/Auth/CredentialsLoader.html#method_getUpdateMetadataFunc", "name": "Google\\Auth\\CredentialsLoader::getUpdateMetadataFunc", "doc": "&quot;export a callback function which updates runtime metadata.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\CredentialsLoader", "fromLink": "Google/Auth/CredentialsLoader.html", "link": "Google/Auth/CredentialsLoader.html#method_updateMetadata", "name": "Google\\Auth\\CredentialsLoader::updateMetadata", "doc": "&quot;Updates metadata with the authorization token.&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\Credentials", "fromLink": "Google/Auth/Credentials.html", "link": "Google/Auth/Credentials/AppIdentityCredentials.html", "name": "Google\\Auth\\Credentials\\AppIdentityCredentials", "doc": "&quot;AppIdentityCredentials supports authorization on Google App Engine.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Credentials\\AppIdentityCredentials", "fromLink": "Google/Auth/Credentials/AppIdentityCredentials.html", "link": "Google/Auth/Credentials/AppIdentityCredentials.html#method___construct", "name": "Google\\Auth\\Credentials\\AppIdentityCredentials::__construct", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\AppIdentityCredentials", "fromLink": "Google/Auth/Credentials/AppIdentityCredentials.html", "link": "Google/Auth/Credentials/AppIdentityCredentials.html#method_onAppEngine", "name": "Google\\Auth\\Credentials\\AppIdentityCredentials::onAppEngine", "doc": "&quot;Determines if this an App Engine instance, by accessing the\nSERVER_SOFTWARE environment variable (prod) or the APPENGINE_RUNTIME\nenvironment variable (dev).&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\AppIdentityCredentials", "fromLink": "Google/Auth/Credentials/AppIdentityCredentials.html", "link": "Google/Auth/Credentials/AppIdentityCredentials.html#method_fetchAuthToken", "name": "Google\\Auth\\Credentials\\AppIdentityCredentials::fetchAuthToken", "doc": "&quot;Implements FetchAuthTokenInterface#fetchAuthToken.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\AppIdentityCredentials", "fromLink": "Google/Auth/Credentials/AppIdentityCredentials.html", "link": "Google/Auth/Credentials/AppIdentityCredentials.html#method_getLastReceivedToken", "name": "Google\\Auth\\Credentials\\AppIdentityCredentials::getLastReceivedToken", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\AppIdentityCredentials", "fromLink": "Google/Auth/Credentials/AppIdentityCredentials.html", "link": "Google/Auth/Credentials/AppIdentityCredentials.html#method_getCacheKey", "name": "Google\\Auth\\Credentials\\AppIdentityCredentials::getCacheKey", "doc": "&quot;Caching is handled by the underlying AppIdentityService, return empty string\nto prevent caching.&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\Credentials", "fromLink": "Google/Auth/Credentials.html", "link": "Google/Auth/Credentials/GCECredentials.html", "name": "Google\\Auth\\Credentials\\GCECredentials", "doc": "&quot;GCECredentials supports authorization on Google Compute Engine.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Credentials\\GCECredentials", "fromLink": "Google/Auth/Credentials/GCECredentials.html", "link": "Google/Auth/Credentials/GCECredentials.html#method_getTokenUri", "name": "Google\\Auth\\Credentials\\GCECredentials::getTokenUri", "doc": "&quot;The full uri for accessing the default token.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\GCECredentials", "fromLink": "Google/Auth/Credentials/GCECredentials.html", "link": "Google/Auth/Credentials/GCECredentials.html#method_onAppEngineFlexible", "name": "Google\\Auth\\Credentials\\GCECredentials::onAppEngineFlexible", "doc": "&quot;Determines if this an App Engine Flexible instance, by accessing the\nGAE_INSTANCE environment variable.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\GCECredentials", "fromLink": "Google/Auth/Credentials/GCECredentials.html", "link": "Google/Auth/Credentials/GCECredentials.html#method_onGce", "name": "Google\\Auth\\Credentials\\GCECredentials::onGce", "doc": "&quot;Determines if this a GCE instance, by accessing the expected metadata\nhost.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\GCECredentials", "fromLink": "Google/Auth/Credentials/GCECredentials.html", "link": "Google/Auth/Credentials/GCECredentials.html#method_fetchAuthToken", "name": "Google\\Auth\\Credentials\\GCECredentials::fetchAuthToken", "doc": "&quot;Implements FetchAuthTokenInterface#fetchAuthToken.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\GCECredentials", "fromLink": "Google/Auth/Credentials/GCECredentials.html", "link": "Google/Auth/Credentials/GCECredentials.html#method_getCacheKey", "name": "Google\\Auth\\Credentials\\GCECredentials::getCacheKey", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\GCECredentials", "fromLink": "Google/Auth/Credentials/GCECredentials.html", "link": "Google/Auth/Credentials/GCECredentials.html#method_getLastReceivedToken", "name": "Google\\Auth\\Credentials\\GCECredentials::getLastReceivedToken", "doc": "&quot;&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\Credentials", "fromLink": "Google/Auth/Credentials.html", "link": "Google/Auth/Credentials/IAMCredentials.html", "name": "Google\\Auth\\Credentials\\IAMCredentials", "doc": "&quot;Authenticates requests using IAM credentials.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Credentials\\IAMCredentials", "fromLink": "Google/Auth/Credentials/IAMCredentials.html", "link": "Google/Auth/Credentials/IAMCredentials.html#method___construct", "name": "Google\\Auth\\Credentials\\IAMCredentials::__construct", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\IAMCredentials", "fromLink": "Google/Auth/Credentials/IAMCredentials.html", "link": "Google/Auth/Credentials/IAMCredentials.html#method_getUpdateMetadataFunc", "name": "Google\\Auth\\Credentials\\IAMCredentials::getUpdateMetadataFunc", "doc": "&quot;export a callback function which updates runtime metadata.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\IAMCredentials", "fromLink": "Google/Auth/Credentials/IAMCredentials.html", "link": "Google/Auth/Credentials/IAMCredentials.html#method_updateMetadata", "name": "Google\\Auth\\Credentials\\IAMCredentials::updateMetadata", "doc": "&quot;Updates metadata with the appropriate header metadata.&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\Credentials", "fromLink": "Google/Auth/Credentials.html", "link": "Google/Auth/Credentials/InsecureCredentials.html", "name": "Google\\Auth\\Credentials\\InsecureCredentials", "doc": "&quot;Provides a set of credentials that will always return an empty access token.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Credentials\\InsecureCredentials", "fromLink": "Google/Auth/Credentials/InsecureCredentials.html", "link": "Google/Auth/Credentials/InsecureCredentials.html#method_fetchAuthToken", "name": "Google\\Auth\\Credentials\\InsecureCredentials::fetchAuthToken", "doc": "&quot;Fetches the auth token. In this case it returns an empty string.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\InsecureCredentials", "fromLink": "Google/Auth/Credentials/InsecureCredentials.html", "link": "Google/Auth/Credentials/InsecureCredentials.html#method_getCacheKey", "name": "Google\\Auth\\Credentials\\InsecureCredentials::getCacheKey", "doc": "&quot;Returns the cache key. In this case it returns a null value, disabling\ncaching.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\InsecureCredentials", "fromLink": "Google/Auth/Credentials/InsecureCredentials.html", "link": "Google/Auth/Credentials/InsecureCredentials.html#method_getLastReceivedToken", "name": "Google\\Auth\\Credentials\\InsecureCredentials::getLastReceivedToken", "doc": "&quot;Fetches the last received token. In this case, it returns the same empty string\nauth token.&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\Credentials", "fromLink": "Google/Auth/Credentials.html", "link": "Google/Auth/Credentials/ServiceAccountCredentials.html", "name": "Google\\Auth\\Credentials\\ServiceAccountCredentials", "doc": "&quot;ServiceAccountCredentials supports authorization using a Google service\naccount.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Credentials\\ServiceAccountCredentials", "fromLink": "Google/Auth/Credentials/ServiceAccountCredentials.html", "link": "Google/Auth/Credentials/ServiceAccountCredentials.html#method___construct", "name": "Google\\Auth\\Credentials\\ServiceAccountCredentials::__construct", "doc": "&quot;Create a new ServiceAccountCredentials.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\ServiceAccountCredentials", "fromLink": "Google/Auth/Credentials/ServiceAccountCredentials.html", "link": "Google/Auth/Credentials/ServiceAccountCredentials.html#method_fetchAuthToken", "name": "Google\\Auth\\Credentials\\ServiceAccountCredentials::fetchAuthToken", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\ServiceAccountCredentials", "fromLink": "Google/Auth/Credentials/ServiceAccountCredentials.html", "link": "Google/Auth/Credentials/ServiceAccountCredentials.html#method_getCacheKey", "name": "Google\\Auth\\Credentials\\ServiceAccountCredentials::getCacheKey", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\ServiceAccountCredentials", "fromLink": "Google/Auth/Credentials/ServiceAccountCredentials.html", "link": "Google/Auth/Credentials/ServiceAccountCredentials.html#method_getLastReceivedToken", "name": "Google\\Auth\\Credentials\\ServiceAccountCredentials::getLastReceivedToken", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\ServiceAccountCredentials", "fromLink": "Google/Auth/Credentials/ServiceAccountCredentials.html", "link": "Google/Auth/Credentials/ServiceAccountCredentials.html#method_updateMetadata", "name": "Google\\Auth\\Credentials\\ServiceAccountCredentials::updateMetadata", "doc": "&quot;Updates metadata with the authorization token.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\ServiceAccountCredentials", "fromLink": "Google/Auth/Credentials/ServiceAccountCredentials.html", "link": "Google/Auth/Credentials/ServiceAccountCredentials.html#method_setSub", "name": "Google\\Auth\\Credentials\\ServiceAccountCredentials::setSub", "doc": "&quot;&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\Credentials", "fromLink": "Google/Auth/Credentials.html", "link": "Google/Auth/Credentials/ServiceAccountJwtAccessCredentials.html", "name": "Google\\Auth\\Credentials\\ServiceAccountJwtAccessCredentials", "doc": "&quot;Authenticates requests using Google&#039;s Service Account credentials via\nJWT Access.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Credentials\\ServiceAccountJwtAccessCredentials", "fromLink": "Google/Auth/Credentials/ServiceAccountJwtAccessCredentials.html", "link": "Google/Auth/Credentials/ServiceAccountJwtAccessCredentials.html#method___construct", "name": "Google\\Auth\\Credentials\\ServiceAccountJwtAccessCredentials::__construct", "doc": "&quot;Create a new ServiceAccountJwtAccessCredentials.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\ServiceAccountJwtAccessCredentials", "fromLink": "Google/Auth/Credentials/ServiceAccountJwtAccessCredentials.html", "link": "Google/Auth/Credentials/ServiceAccountJwtAccessCredentials.html#method_updateMetadata", "name": "Google\\Auth\\Credentials\\ServiceAccountJwtAccessCredentials::updateMetadata", "doc": "&quot;Updates metadata with the authorization token.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\ServiceAccountJwtAccessCredentials", "fromLink": "Google/Auth/Credentials/ServiceAccountJwtAccessCredentials.html", "link": "Google/Auth/Credentials/ServiceAccountJwtAccessCredentials.html#method_fetchAuthToken", "name": "Google\\Auth\\Credentials\\ServiceAccountJwtAccessCredentials::fetchAuthToken", "doc": "&quot;Implements FetchAuthTokenInterface#fetchAuthToken.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\ServiceAccountJwtAccessCredentials", "fromLink": "Google/Auth/Credentials/ServiceAccountJwtAccessCredentials.html", "link": "Google/Auth/Credentials/ServiceAccountJwtAccessCredentials.html#method_getCacheKey", "name": "Google\\Auth\\Credentials\\ServiceAccountJwtAccessCredentials::getCacheKey", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\ServiceAccountJwtAccessCredentials", "fromLink": "Google/Auth/Credentials/ServiceAccountJwtAccessCredentials.html", "link": "Google/Auth/Credentials/ServiceAccountJwtAccessCredentials.html#method_getLastReceivedToken", "name": "Google\\Auth\\Credentials\\ServiceAccountJwtAccessCredentials::getLastReceivedToken", "doc": "&quot;&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\Credentials", "fromLink": "Google/Auth/Credentials.html", "link": "Google/Auth/Credentials/UserRefreshCredentials.html", "name": "Google\\Auth\\Credentials\\UserRefreshCredentials", "doc": "&quot;Authenticates requests using User Refresh credentials.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Credentials\\UserRefreshCredentials", "fromLink": "Google/Auth/Credentials/UserRefreshCredentials.html", "link": "Google/Auth/Credentials/UserRefreshCredentials.html#method___construct", "name": "Google\\Auth\\Credentials\\UserRefreshCredentials::__construct", "doc": "&quot;Create a new UserRefreshCredentials.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\UserRefreshCredentials", "fromLink": "Google/Auth/Credentials/UserRefreshCredentials.html", "link": "Google/Auth/Credentials/UserRefreshCredentials.html#method_fetchAuthToken", "name": "Google\\Auth\\Credentials\\UserRefreshCredentials::fetchAuthToken", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\UserRefreshCredentials", "fromLink": "Google/Auth/Credentials/UserRefreshCredentials.html", "link": "Google/Auth/Credentials/UserRefreshCredentials.html#method_getCacheKey", "name": "Google\\Auth\\Credentials\\UserRefreshCredentials::getCacheKey", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Credentials\\UserRefreshCredentials", "fromLink": "Google/Auth/Credentials/UserRefreshCredentials.html", "link": "Google/Auth/Credentials/UserRefreshCredentials.html#method_getLastReceivedToken", "name": "Google\\Auth\\Credentials\\UserRefreshCredentials::getLastReceivedToken", "doc": "&quot;&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth", "fromLink": "Google/Auth.html", "link": "Google/Auth/FetchAuthTokenCache.html", "name": "Google\\Auth\\FetchAuthTokenCache", "doc": "&quot;A class to implement caching for any object implementing\nFetchAuthTokenInterface&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\FetchAuthTokenCache", "fromLink": "Google/Auth/FetchAuthTokenCache.html", "link": "Google/Auth/FetchAuthTokenCache.html#method___construct", "name": "Google\\Auth\\FetchAuthTokenCache::__construct", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\FetchAuthTokenCache", "fromLink": "Google/Auth/FetchAuthTokenCache.html", "link": "Google/Auth/FetchAuthTokenCache.html#method_fetchAuthToken", "name": "Google\\Auth\\FetchAuthTokenCache::fetchAuthToken", "doc": "&quot;Implements FetchAuthTokenInterface#fetchAuthToken.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\FetchAuthTokenCache", "fromLink": "Google/Auth/FetchAuthTokenCache.html", "link": "Google/Auth/FetchAuthTokenCache.html#method_getCacheKey", "name": "Google\\Auth\\FetchAuthTokenCache::getCacheKey", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\FetchAuthTokenCache", "fromLink": "Google/Auth/FetchAuthTokenCache.html", "link": "Google/Auth/FetchAuthTokenCache.html#method_getLastReceivedToken", "name": "Google\\Auth\\FetchAuthTokenCache::getLastReceivedToken", "doc": "&quot;&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth", "fromLink": "Google/Auth.html", "link": "Google/Auth/FetchAuthTokenInterface.html", "name": "Google\\Auth\\FetchAuthTokenInterface", "doc": "&quot;An interface implemented by objects that can fetch auth tokens.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\FetchAuthTokenInterface", "fromLink": "Google/Auth/FetchAuthTokenInterface.html", "link": "Google/Auth/FetchAuthTokenInterface.html#method_fetchAuthToken", "name": "Google\\Auth\\FetchAuthTokenInterface::fetchAuthToken", "doc": "&quot;Fetches the auth tokens based on the current state.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\FetchAuthTokenInterface", "fromLink": "Google/Auth/FetchAuthTokenInterface.html", "link": "Google/Auth/FetchAuthTokenInterface.html#method_getCacheKey", "name": "Google\\Auth\\FetchAuthTokenInterface::getCacheKey", "doc": "&quot;Obtains a key that can used to cache the results of #fetchAuthToken.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\FetchAuthTokenInterface", "fromLink": "Google/Auth/FetchAuthTokenInterface.html", "link": "Google/Auth/FetchAuthTokenInterface.html#method_getLastReceivedToken", "name": "Google\\Auth\\FetchAuthTokenInterface::getLastReceivedToken", "doc": "&quot;Returns an associative array with the token and\nexpiration time.&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\HttpHandler", "fromLink": "Google/Auth/HttpHandler.html", "link": "Google/Auth/HttpHandler/Guzzle5HttpHandler.html", "name": "Google\\Auth\\HttpHandler\\Guzzle5HttpHandler", "doc": "&quot;&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\HttpHandler\\Guzzle5HttpHandler", "fromLink": "Google/Auth/HttpHandler/Guzzle5HttpHandler.html", "link": "Google/Auth/HttpHandler/Guzzle5HttpHandler.html#method___construct", "name": "Google\\Auth\\HttpHandler\\Guzzle5HttpHandler::__construct", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\HttpHandler\\Guzzle5HttpHandler", "fromLink": "Google/Auth/HttpHandler/Guzzle5HttpHandler.html", "link": "Google/Auth/HttpHandler/Guzzle5HttpHandler.html#method___invoke", "name": "Google\\Auth\\HttpHandler\\Guzzle5HttpHandler::__invoke", "doc": "&quot;Accepts a PSR-7 Request and an array of options and returns a PSR-7 response.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\HttpHandler\\Guzzle5HttpHandler", "fromLink": "Google/Auth/HttpHandler/Guzzle5HttpHandler.html", "link": "Google/Auth/HttpHandler/Guzzle5HttpHandler.html#method_async", "name": "Google\\Auth\\HttpHandler\\Guzzle5HttpHandler::async", "doc": "&quot;Accepts a PSR-7 request and an array of options and returns a PromiseInterface&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\HttpHandler", "fromLink": "Google/Auth/HttpHandler.html", "link": "Google/Auth/HttpHandler/Guzzle6HttpHandler.html", "name": "Google\\Auth\\HttpHandler\\Guzzle6HttpHandler", "doc": "&quot;&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\HttpHandler\\Guzzle6HttpHandler", "fromLink": "Google/Auth/HttpHandler/Guzzle6HttpHandler.html", "link": "Google/Auth/HttpHandler/Guzzle6HttpHandler.html#method___construct", "name": "Google\\Auth\\HttpHandler\\Guzzle6HttpHandler::__construct", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\HttpHandler\\Guzzle6HttpHandler", "fromLink": "Google/Auth/HttpHandler/Guzzle6HttpHandler.html", "link": "Google/Auth/HttpHandler/Guzzle6HttpHandler.html#method___invoke", "name": "Google\\Auth\\HttpHandler\\Guzzle6HttpHandler::__invoke", "doc": "&quot;Accepts a PSR-7 request and an array of options and returns a PSR-7 response.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\HttpHandler\\Guzzle6HttpHandler", "fromLink": "Google/Auth/HttpHandler/Guzzle6HttpHandler.html", "link": "Google/Auth/HttpHandler/Guzzle6HttpHandler.html#method_async", "name": "Google\\Auth\\HttpHandler\\Guzzle6HttpHandler::async", "doc": "&quot;Accepts a PSR-7 request and an array of options and returns a PromiseInterface&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\HttpHandler", "fromLink": "Google/Auth/HttpHandler.html", "link": "Google/Auth/HttpHandler/HttpHandlerFactory.html", "name": "Google\\Auth\\HttpHandler\\HttpHandlerFactory", "doc": "&quot;&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\HttpHandler\\HttpHandlerFactory", "fromLink": "Google/Auth/HttpHandler/HttpHandlerFactory.html", "link": "Google/Auth/HttpHandler/HttpHandlerFactory.html#method_build", "name": "Google\\Auth\\HttpHandler\\HttpHandlerFactory::build", "doc": "&quot;Builds out a default http handler for the installed version of guzzle.&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\Middleware", "fromLink": "Google/Auth/Middleware.html", "link": "Google/Auth/Middleware/AuthTokenMiddleware.html", "name": "Google\\Auth\\Middleware\\AuthTokenMiddleware", "doc": "&quot;AuthTokenMiddleware is a Guzzle Middleware that adds an Authorization header\nprovided by an object implementing FetchAuthTokenInterface.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Middleware\\AuthTokenMiddleware", "fromLink": "Google/Auth/Middleware/AuthTokenMiddleware.html", "link": "Google/Auth/Middleware/AuthTokenMiddleware.html#method___construct", "name": "Google\\Auth\\Middleware\\AuthTokenMiddleware::__construct", "doc": "&quot;Creates a new AuthTokenMiddleware.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Middleware\\AuthTokenMiddleware", "fromLink": "Google/Auth/Middleware/AuthTokenMiddleware.html", "link": "Google/Auth/Middleware/AuthTokenMiddleware.html#method___invoke", "name": "Google\\Auth\\Middleware\\AuthTokenMiddleware::__invoke", "doc": "&quot;Updates the request with an Authorization header when auth is &#039;google_auth&#039;.&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\Middleware", "fromLink": "Google/Auth/Middleware.html", "link": "Google/Auth/Middleware/ScopedAccessTokenMiddleware.html", "name": "Google\\Auth\\Middleware\\ScopedAccessTokenMiddleware", "doc": "&quot;ScopedAccessTokenMiddleware is a Guzzle Middleware that adds an Authorization\nheader provided by a closure.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Middleware\\ScopedAccessTokenMiddleware", "fromLink": "Google/Auth/Middleware/ScopedAccessTokenMiddleware.html", "link": "Google/Auth/Middleware/ScopedAccessTokenMiddleware.html#method___construct", "name": "Google\\Auth\\Middleware\\ScopedAccessTokenMiddleware::__construct", "doc": "&quot;Creates a new ScopedAccessTokenMiddleware.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Middleware\\ScopedAccessTokenMiddleware", "fromLink": "Google/Auth/Middleware/ScopedAccessTokenMiddleware.html", "link": "Google/Auth/Middleware/ScopedAccessTokenMiddleware.html#method___invoke", "name": "Google\\Auth\\Middleware\\ScopedAccessTokenMiddleware::__invoke", "doc": "&quot;Updates the request with an Authorization header when auth is &#039;scoped&#039;.&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\Middleware", "fromLink": "Google/Auth/Middleware.html", "link": "Google/Auth/Middleware/SimpleMiddleware.html", "name": "Google\\Auth\\Middleware\\SimpleMiddleware", "doc": "&quot;SimpleMiddleware is a Guzzle Middleware that implements Google&#039;s Simple API\naccess.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Middleware\\SimpleMiddleware", "fromLink": "Google/Auth/Middleware/SimpleMiddleware.html", "link": "Google/Auth/Middleware/SimpleMiddleware.html#method___construct", "name": "Google\\Auth\\Middleware\\SimpleMiddleware::__construct", "doc": "&quot;Create a new Simple plugin.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Middleware\\SimpleMiddleware", "fromLink": "Google/Auth/Middleware/SimpleMiddleware.html", "link": "Google/Auth/Middleware/SimpleMiddleware.html#method___invoke", "name": "Google\\Auth\\Middleware\\SimpleMiddleware::__invoke", "doc": "&quot;Updates the request query with the developer key if auth is set to simple.&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth", "fromLink": "Google/Auth.html", "link": "Google/Auth/OAuth2.html", "name": "Google\\Auth\\OAuth2", "doc": "&quot;OAuth2 supports authentication by OAuth2 2-legged flows.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method___construct", "name": "Google\\Auth\\OAuth2::__construct", "doc": "&quot;Create a new OAuthCredentials.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_verifyIdToken", "name": "Google\\Auth\\OAuth2::verifyIdToken", "doc": "&quot;Verifies the idToken if present.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_toJwt", "name": "Google\\Auth\\OAuth2::toJwt", "doc": "&quot;Obtains the encoded jwt from the instance data.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_generateCredentialsRequest", "name": "Google\\Auth\\OAuth2::generateCredentialsRequest", "doc": "&quot;Generates a request for token credentials.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_fetchAuthToken", "name": "Google\\Auth\\OAuth2::fetchAuthToken", "doc": "&quot;Fetches the auth tokens based on the current state.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getCacheKey", "name": "Google\\Auth\\OAuth2::getCacheKey", "doc": "&quot;Obtains a key that can used to cache the results of #fetchAuthToken.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_parseTokenResponse", "name": "Google\\Auth\\OAuth2::parseTokenResponse", "doc": "&quot;Parses the fetched tokens.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_updateToken", "name": "Google\\Auth\\OAuth2::updateToken", "doc": "&quot;Updates an OAuth 2.0 client.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_buildFullAuthorizationUri", "name": "Google\\Auth\\OAuth2::buildFullAuthorizationUri", "doc": "&quot;Builds the authorization Uri that the user should be redirected to.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setAuthorizationUri", "name": "Google\\Auth\\OAuth2::setAuthorizationUri", "doc": "&quot;Sets the authorization server&#039;s HTTP endpoint capable of authenticating\nthe end-user and obtaining authorization.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getAuthorizationUri", "name": "Google\\Auth\\OAuth2::getAuthorizationUri", "doc": "&quot;Gets the authorization server&#039;s HTTP endpoint capable of authenticating\nthe end-user and obtaining authorization.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getTokenCredentialUri", "name": "Google\\Auth\\OAuth2::getTokenCredentialUri", "doc": "&quot;Gets the authorization server&#039;s HTTP endpoint capable of issuing tokens\nand refreshing expired tokens.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setTokenCredentialUri", "name": "Google\\Auth\\OAuth2::setTokenCredentialUri", "doc": "&quot;Sets the authorization server&#039;s HTTP endpoint capable of issuing tokens\nand refreshing expired tokens.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getRedirectUri", "name": "Google\\Auth\\OAuth2::getRedirectUri", "doc": "&quot;Gets the redirection URI used in the initial request.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setRedirectUri", "name": "Google\\Auth\\OAuth2::setRedirectUri", "doc": "&quot;Sets the redirection URI used in the initial request.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getScope", "name": "Google\\Auth\\OAuth2::getScope", "doc": "&quot;Gets the scope of the access requests as a space-delimited String.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setScope", "name": "Google\\Auth\\OAuth2::setScope", "doc": "&quot;Sets the scope of the access request, expressed either as an Array or as\na space-delimited String.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getGrantType", "name": "Google\\Auth\\OAuth2::getGrantType", "doc": "&quot;Gets the current grant type.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setGrantType", "name": "Google\\Auth\\OAuth2::setGrantType", "doc": "&quot;Sets the current grant type.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getState", "name": "Google\\Auth\\OAuth2::getState", "doc": "&quot;Gets an arbitrary string designed to allow the client to maintain state.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setState", "name": "Google\\Auth\\OAuth2::setState", "doc": "&quot;Sets an arbitrary string designed to allow the client to maintain state.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getCode", "name": "Google\\Auth\\OAuth2::getCode", "doc": "&quot;Gets the authorization code issued to this client.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setCode", "name": "Google\\Auth\\OAuth2::setCode", "doc": "&quot;Sets the authorization code issued to this client.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getUsername", "name": "Google\\Auth\\OAuth2::getUsername", "doc": "&quot;Gets the resource owner&#039;s username.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setUsername", "name": "Google\\Auth\\OAuth2::setUsername", "doc": "&quot;Sets the resource owner&#039;s username.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getPassword", "name": "Google\\Auth\\OAuth2::getPassword", "doc": "&quot;Gets the resource owner&#039;s password.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setPassword", "name": "Google\\Auth\\OAuth2::setPassword", "doc": "&quot;Sets the resource owner&#039;s password.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getClientId", "name": "Google\\Auth\\OAuth2::getClientId", "doc": "&quot;Sets a unique identifier issued to the client to identify itself to the\nauthorization server.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setClientId", "name": "Google\\Auth\\OAuth2::setClientId", "doc": "&quot;Sets a unique identifier issued to the client to identify itself to the\nauthorization server.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getClientSecret", "name": "Google\\Auth\\OAuth2::getClientSecret", "doc": "&quot;Gets a shared symmetric secret issued by the authorization server, which\nis used to authenticate the client.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setClientSecret", "name": "Google\\Auth\\OAuth2::setClientSecret", "doc": "&quot;Sets a shared symmetric secret issued by the authorization server, which\nis used to authenticate the client.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getIssuer", "name": "Google\\Auth\\OAuth2::getIssuer", "doc": "&quot;Gets the Issuer ID when using assertion profile.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setIssuer", "name": "Google\\Auth\\OAuth2::setIssuer", "doc": "&quot;Sets the Issuer ID when using assertion profile.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getSub", "name": "Google\\Auth\\OAuth2::getSub", "doc": "&quot;Gets the target sub when issuing assertions.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setSub", "name": "Google\\Auth\\OAuth2::setSub", "doc": "&quot;Sets the target sub when issuing assertions.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getAudience", "name": "Google\\Auth\\OAuth2::getAudience", "doc": "&quot;Gets the target audience when issuing assertions.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setAudience", "name": "Google\\Auth\\OAuth2::setAudience", "doc": "&quot;Sets the target audience when issuing assertions.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getSigningKey", "name": "Google\\Auth\\OAuth2::getSigningKey", "doc": "&quot;Gets the signing key when using an assertion profile.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setSigningKey", "name": "Google\\Auth\\OAuth2::setSigningKey", "doc": "&quot;Sets the signing key when using an assertion profile.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getSigningAlgorithm", "name": "Google\\Auth\\OAuth2::getSigningAlgorithm", "doc": "&quot;Gets the signing algorithm when using an assertion profile.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setSigningAlgorithm", "name": "Google\\Auth\\OAuth2::setSigningAlgorithm", "doc": "&quot;Sets the signing algorithm when using an assertion profile.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getExtensionParams", "name": "Google\\Auth\\OAuth2::getExtensionParams", "doc": "&quot;Gets the set of parameters used by extension when using an extension\ngrant type.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setExtensionParams", "name": "Google\\Auth\\OAuth2::setExtensionParams", "doc": "&quot;Sets the set of parameters used by extension when using an extension\ngrant type.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getExpiry", "name": "Google\\Auth\\OAuth2::getExpiry", "doc": "&quot;Gets the number of seconds assertions are valid for.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setExpiry", "name": "Google\\Auth\\OAuth2::setExpiry", "doc": "&quot;Sets the number of seconds assertions are valid for.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getExpiresIn", "name": "Google\\Auth\\OAuth2::getExpiresIn", "doc": "&quot;Gets the lifetime of the access token in seconds.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setExpiresIn", "name": "Google\\Auth\\OAuth2::setExpiresIn", "doc": "&quot;Sets the lifetime of the access token in seconds.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getExpiresAt", "name": "Google\\Auth\\OAuth2::getExpiresAt", "doc": "&quot;Gets the time the current access token expires at.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_isExpired", "name": "Google\\Auth\\OAuth2::isExpired", "doc": "&quot;Returns true if the acccess token has expired.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setExpiresAt", "name": "Google\\Auth\\OAuth2::setExpiresAt", "doc": "&quot;Sets the time the current access token expires at.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getIssuedAt", "name": "Google\\Auth\\OAuth2::getIssuedAt", "doc": "&quot;Gets the time the current access token was issued at.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setIssuedAt", "name": "Google\\Auth\\OAuth2::setIssuedAt", "doc": "&quot;Sets the time the current access token was issued at.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getAccessToken", "name": "Google\\Auth\\OAuth2::getAccessToken", "doc": "&quot;Gets the current access token.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setAccessToken", "name": "Google\\Auth\\OAuth2::setAccessToken", "doc": "&quot;Sets the current access token.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getIdToken", "name": "Google\\Auth\\OAuth2::getIdToken", "doc": "&quot;Gets the current ID token.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setIdToken", "name": "Google\\Auth\\OAuth2::setIdToken", "doc": "&quot;Sets the current ID token.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getRefreshToken", "name": "Google\\Auth\\OAuth2::getRefreshToken", "doc": "&quot;Gets the refresh token associated with the current access token.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setRefreshToken", "name": "Google\\Auth\\OAuth2::setRefreshToken", "doc": "&quot;Sets the refresh token associated with the current access token.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_setAdditionalClaims", "name": "Google\\Auth\\OAuth2::setAdditionalClaims", "doc": "&quot;Sets additional claims to be included in the JWT token&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getAdditionalClaims", "name": "Google\\Auth\\OAuth2::getAdditionalClaims", "doc": "&quot;Gets the additional claims to be included in the JWT token.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\OAuth2", "fromLink": "Google/Auth/OAuth2.html", "link": "Google/Auth/OAuth2.html#method_getLastReceivedToken", "name": "Google\\Auth\\OAuth2::getLastReceivedToken", "doc": "&quot;The expiration of the last received token.&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\Subscriber", "fromLink": "Google/Auth/Subscriber.html", "link": "Google/Auth/Subscriber/AuthTokenSubscriber.html", "name": "Google\\Auth\\Subscriber\\AuthTokenSubscriber", "doc": "&quot;AuthTokenSubscriber is a Guzzle Subscriber that adds an Authorization header\nprovided by an object implementing FetchAuthTokenInterface.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Subscriber\\AuthTokenSubscriber", "fromLink": "Google/Auth/Subscriber/AuthTokenSubscriber.html", "link": "Google/Auth/Subscriber/AuthTokenSubscriber.html#method___construct", "name": "Google\\Auth\\Subscriber\\AuthTokenSubscriber::__construct", "doc": "&quot;Creates a new AuthTokenSubscriber.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Subscriber\\AuthTokenSubscriber", "fromLink": "Google/Auth/Subscriber/AuthTokenSubscriber.html", "link": "Google/Auth/Subscriber/AuthTokenSubscriber.html#method_getEvents", "name": "Google\\Auth\\Subscriber\\AuthTokenSubscriber::getEvents", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Subscriber\\AuthTokenSubscriber", "fromLink": "Google/Auth/Subscriber/AuthTokenSubscriber.html", "link": "Google/Auth/Subscriber/AuthTokenSubscriber.html#method_onBefore", "name": "Google\\Auth\\Subscriber\\AuthTokenSubscriber::onBefore", "doc": "&quot;Updates the request with an Authorization header when auth is &#039;fetched_auth_token&#039;.&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\Subscriber", "fromLink": "Google/Auth/Subscriber.html", "link": "Google/Auth/Subscriber/ScopedAccessTokenSubscriber.html", "name": "Google\\Auth\\Subscriber\\ScopedAccessTokenSubscriber", "doc": "&quot;ScopedAccessTokenSubscriber is a Guzzle Subscriber that adds an Authorization\nheader provided by a closure.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Subscriber\\ScopedAccessTokenSubscriber", "fromLink": "Google/Auth/Subscriber/ScopedAccessTokenSubscriber.html", "link": "Google/Auth/Subscriber/ScopedAccessTokenSubscriber.html#method___construct", "name": "Google\\Auth\\Subscriber\\ScopedAccessTokenSubscriber::__construct", "doc": "&quot;Creates a new ScopedAccessTokenSubscriber.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Subscriber\\ScopedAccessTokenSubscriber", "fromLink": "Google/Auth/Subscriber/ScopedAccessTokenSubscriber.html", "link": "Google/Auth/Subscriber/ScopedAccessTokenSubscriber.html#method_getEvents", "name": "Google\\Auth\\Subscriber\\ScopedAccessTokenSubscriber::getEvents", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Subscriber\\ScopedAccessTokenSubscriber", "fromLink": "Google/Auth/Subscriber/ScopedAccessTokenSubscriber.html", "link": "Google/Auth/Subscriber/ScopedAccessTokenSubscriber.html#method_onBefore", "name": "Google\\Auth\\Subscriber\\ScopedAccessTokenSubscriber::onBefore", "doc": "&quot;Updates the request with an Authorization header when auth is &#039;scoped&#039;.&quot;"},
            
            {"type": "Class", "fromName": "Google\\Auth\\Subscriber", "fromLink": "Google/Auth/Subscriber.html", "link": "Google/Auth/Subscriber/SimpleSubscriber.html", "name": "Google\\Auth\\Subscriber\\SimpleSubscriber", "doc": "&quot;SimpleSubscriber is a Guzzle Subscriber that implements Google&#039;s Simple API\naccess.&quot;"},
                                                        {"type": "Method", "fromName": "Google\\Auth\\Subscriber\\SimpleSubscriber", "fromLink": "Google/Auth/Subscriber/SimpleSubscriber.html", "link": "Google/Auth/Subscriber/SimpleSubscriber.html#method___construct", "name": "Google\\Auth\\Subscriber\\SimpleSubscriber::__construct", "doc": "&quot;Create a new Simple plugin.&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Subscriber\\SimpleSubscriber", "fromLink": "Google/Auth/Subscriber/SimpleSubscriber.html", "link": "Google/Auth/Subscriber/SimpleSubscriber.html#method_getEvents", "name": "Google\\Auth\\Subscriber\\SimpleSubscriber::getEvents", "doc": "&quot;&quot;"},
                    {"type": "Method", "fromName": "Google\\Auth\\Subscriber\\SimpleSubscriber", "fromLink": "Google/Auth/Subscriber/SimpleSubscriber.html", "link": "Google/Auth/Subscriber/SimpleSubscriber.html#method_onBefore", "name": "Google\\Auth\\Subscriber\\SimpleSubscriber::onBefore", "doc": "&quot;Updates the request query with the developer key if auth is set to simple.&quot;"},
            
            
                                        // Fix trailing commas in the index
        {}
    ];

    /** Tokenizes strings by namespaces and functions */
    function tokenizer(term) {
        if (!term) {
            return [];
        }

        var tokens = [term];
        var meth = term.indexOf('::');

        // Split tokens into methods if "::" is found.
        if (meth > -1) {
            tokens.push(term.substr(meth + 2));
            term = term.substr(0, meth - 2);
        }

        // Split by namespace or fake namespace.
        if (term.indexOf('\\') > -1) {
            tokens = tokens.concat(term.split('\\'));
        } else if (term.indexOf('_') > 0) {
            tokens = tokens.concat(term.split('_'));
        }

        // Merge in splitting the string by case and return
        tokens = tokens.concat(term.match(/(([A-Z]?[^A-Z]*)|([a-z]?[^a-z]*))/g).slice(0,-1));

        return tokens;
    };

    root.Sami = {
        /**
         * Cleans the provided term. If no term is provided, then one is
         * grabbed from the query string "search" parameter.
         */
        cleanSearchTerm: function(term) {
            // Grab from the query string
            if (typeof term === 'undefined') {
                var name = 'search';
                var regex = new RegExp("[\\?&]" + name + "=([^&#]*)");
                var results = regex.exec(location.search);
                if (results === null) {
                    return null;
                }
                term = decodeURIComponent(results[1].replace(/\+/g, " "));
            }

            return term.replace(/<(?:.|\n)*?>/gm, '');
        },

        /** Searches through the index for a given term */
        search: function(term) {
            // Create a new search index if needed
            if (!bhIndex) {
                bhIndex = new Bloodhound({
                    limit: 500,
                    local: searchIndex,
                    datumTokenizer: function (d) {
                        return tokenizer(d.name);
                    },
                    queryTokenizer: Bloodhound.tokenizers.whitespace
                });
                bhIndex.initialize();
            }

            results = [];
            bhIndex.get(term, function(matches) {
                results = matches;
            });

            if (!rootPath) {
                return results;
            }

            // Fix the element links based on the current page depth.
            return $.map(results, function(ele) {
                if (ele.link.indexOf('..') > -1) {
                    return ele;
                }
                ele.link = rootPath + ele.link;
                if (ele.fromLink) {
                    ele.fromLink = rootPath + ele.fromLink;
                }
                return ele;
            });
        },

        /** Get a search class for a specific type */
        getSearchClass: function(type) {
            return searchTypeClasses[type] || searchTypeClasses['_'];
        },

        /** Add the left-nav tree to the site */
        injectApiTree: function(ele) {
            ele.html(treeHtml);
        }
    };

    $(function() {
        // Modify the HTML to work correctly based on the current depth
        rootPath = $('body').attr('data-root-path');
        treeHtml = treeHtml.replace(/href="/g, 'href="' + rootPath);
        Sami.injectApiTree($('#api-tree'));
    });

    return root.Sami;
})(window);

$(function() {

    // Enable the version switcher
    $('#version-switcher').change(function() {
        window.location = $(this).val()
    });

    
        // Toggle left-nav divs on click
        $('#api-tree .hd span').click(function() {
            $(this).parent().parent().toggleClass('opened');
        });

        // Expand the parent namespaces of the current page.
        var expected = $('body').attr('data-name');

        if (expected) {
            // Open the currently selected node and its parents.
            var container = $('#api-tree');
            var node = $('#api-tree li[data-name="' + expected + '"]');
            // Node might not be found when simulating namespaces
            if (node.length > 0) {
                node.addClass('active').addClass('opened');
                node.parents('li').addClass('opened');
                var scrollPos = node.offset().top - container.offset().top + container.scrollTop();
                // Position the item nearer to the top of the screen.
                scrollPos -= 200;
                container.scrollTop(scrollPos);
            }
        }

    
    
        var form = $('#search-form .typeahead');
        form.typeahead({
            hint: true,
            highlight: true,
            minLength: 1
        }, {
            name: 'search',
            displayKey: 'name',
            source: function (q, cb) {
                cb(Sami.search(q));
            }
        });

        // The selection is direct-linked when the user selects a suggestion.
        form.on('typeahead:selected', function(e, suggestion) {
            window.location = suggestion.link;
        });

        // The form is submitted when the user hits enter.
        form.keypress(function (e) {
            if (e.which == 13) {
                $('#search-form').submit();
                return true;
            }
        });

    
});


