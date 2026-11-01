/*
 * FIXTURE: Angular escapes everything it renders - unless the code tells it
 * not to, with DomSanitizer.bypassSecurityTrust*(). Juice Shop's two marked
 * XSS lines are this call, and Defuse knew neither the call nor Angular's
 * route parameters, so both were silent.
 */
import { Component } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({ selector: 'app-search', template: '<div [innerHTML]="searchValue"></div>' })
export class SearchComponent {
  searchValue: SafeHtml = '';

  constructor(private route: ActivatedRoute, private sanitizer: DomSanitizer) {}

  // Juice Shop's search box (localXssChallenge): the address bar, trusted as HTML.
  filter(): void {
    let queryParam: string = this.route.snapshot.queryParams.q;
    queryParam = queryParam.trim();
    // EXPECT-FLOW xss
    this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam);
  }

  // A product description from the API (restfulXssChallenge): stored data, so
  // a fair guess rather than a proof.
  show(description: string): SafeHtml {
    // EXPECT-SIGNATURE xss
    return this.sanitizer.bypassSecurityTrustHtml(description);
  }
}
