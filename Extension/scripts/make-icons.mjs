#!/usr/bin/env node
// Writes icons/icon.svg and icons/icon-{16,32,48,128}.png from the logo defined in the Core repository.
import { writeExtensionIcons } from '../../Core/desktop-app/scripts/make-icons.mjs';

writeExtensionIcons();
