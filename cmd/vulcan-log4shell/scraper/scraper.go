package scraper

import (
	"net/url"
	"sync"

	"github.com/gocolly/colly"
	"github.com/gocolly/colly/debug"
)

// Scrap scraps the given url up to the maximun given depth, by following all
// the ``a[href]`` elements of the page.
func Scrap(u *url.URL, depth uint) ([]string, error) {
	c := colly.NewCollector(
		colly.Async(true),
		colly.Debugger(&debug.LogDebugger{}),
		colly.AllowedDomains(u.Host),
		colly.MaxDepth(int(depth)),
	)
	c.Limit(&colly.LimitRule{
		Parallelism: 4,
	})

	found := sync.Map{}
	c.OnHTML("a", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		u := e.Request.AbsoluteURL(link)
		found.Store(u, struct{}{})
		c.Visit(u)
	})

	err := c.Visit(u.String())
	if err != nil {
		return nil, err
	}
	c.Wait()
	urls := []string{}
	found.Range(func(key, value interface{}) bool {
		urls = append(urls, key.(string))
		return true
	})
	return urls, nil
}
