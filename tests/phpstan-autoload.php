<?php

require_once __DIR__ . '/../vendor/autoload.php';

// moc the windows-only COM class so that the autoloader understands it
if (!class_exists(COM::class)) {
    class COM
    {
        public function __construct(string $command)
        {
            //do nothing
        }
        
        public function regRead(string $key): string
        {
            // do nothing
            return '';
        }
    }
}
